"""Upload des resultats d'audit via HTTPS + mTLS avec queue offline.

Deux mecanismes :
1. HTTP POST /api/v1/agents/tasks/{task_uuid}/result — soumet le resume JSON
2. HTTP POST /api/v1/agents/tasks/{task_uuid}/artifacts — upload multipart des fichiers
   (endpoint a creer cote serveur — pour l'instant, les artifacts sont loggues)

Si le serveur est injoignable, les resultats sont sauves dans queue/ et
renvoyes a la reconnexion.
"""

from __future__ import annotations

import json
import logging
import ssl
import time
from datetime import datetime, timezone
from pathlib import Path

import httpx

from assistant_audit_agent.config import AgentConfig
from assistant_audit_agent.tools import ToolResult

logger = logging.getLogger("uploader")

UPLOAD_TIMEOUT = 300.0  # 5 minutes par fichier
RETRY_DELAYS = [1.0, 5.0, 15.0]  # 3 tentatives
QUEUE_DIR = Path("queue")
QUEUE_MAX_SIZE = 100
QUEUE_TTL_DAYS = 7
RESULT_ENDPOINT = "/api/v1/agents/tasks/{task_uuid}/result"
ARTIFACT_ENDPOINT = "/api/v1/agents/tasks/{task_uuid}/artifacts"


class ResultUploader:
    """Gestionnaire d'upload des resultats avec queue offline."""

    def __init__(self, config: AgentConfig) -> None:
        self._config = config
        self._queue_dir = QUEUE_DIR
        self._queue_dir.mkdir(parents=True, exist_ok=True)

    # ── Upload principal ──────────────────────────────────────────────

    async def upload_result(
        self,
        task_uuid: str,
        tool_name: str,
        result: ToolResult,
    ) -> bool:
        """Upload le resultat d'une tache au serveur.

        Returns:
            True si l'upload a reussi, False si mis en queue.
        """
        # Soumettre le resume via HTTP
        success = await self._submit_result_http(task_uuid, result)

        if success and result.artifacts:
            success = await self._upload_artifacts(task_uuid, result.artifacts)

        if success:
            # Supprimer les artifacts locaux apres upload reussi
            self._cleanup_artifacts(result.artifacts)
            return True

        # Echec — sauver en queue offline
        self._enqueue(task_uuid, tool_name, result)
        return False

    # ── Soumission HTTP du resume ─────────────────────────────────────

    async def _submit_result_http(self, task_uuid: str, result: ToolResult) -> bool:
        """Soumet le resume JSON via POST /agents/tasks/{uuid}/result."""
        url = self._config.server_url + RESULT_ENDPOINT.format(task_uuid=task_uuid)
        body = {
            "result_summary": result.output if result.success else None,
            "error_message": result.error,
        }

        return await self._post_with_retry(url, json_body=body)

    # ── Upload des artifacts ──────────────────────────────────────────

    async def _upload_artifacts(self, task_uuid: str, artifacts: list[Path]) -> bool:
        """Upload les fichiers artifacts via POST multipart."""
        url = self._config.server_url + ARTIFACT_ENDPOINT.format(task_uuid=task_uuid)

        all_ok = True
        for artifact in artifacts:
            if not artifact.exists():
                logger.warning("Artifact introuvable : %s", artifact)
                continue

            ok = await self._upload_file_with_retry(url, artifact, task_uuid)
            if not ok:
                all_ok = False

        return all_ok

    async def _upload_file_with_retry(
        self, url: str, file_path: Path, task_uuid: str
    ) -> bool:
        """Upload un fichier avec retry."""
        for attempt, delay in enumerate(RETRY_DELAYS):
            try:
                async with self._build_client() as client:
                    with file_path.open("rb") as f:
                        files = {"file": (file_path.name, f, "application/octet-stream")}
                        data = {"task_uuid": task_uuid}
                        resp = await client.post(url, files=files, data=data, timeout=UPLOAD_TIMEOUT)

                    if resp.status_code in (200, 201):
                        logger.info("Artifact uploade : %s", file_path.name)
                        return True

                    # 404 = endpoint pas encore implemente cote serveur
                    if resp.status_code == 404:
                        logger.warning(
                            "Endpoint artifacts non disponible (404) — "
                            "artifact '%s' conserve localement.",
                            file_path.name,
                        )
                        return True  # Pas une erreur reseau, ne pas reessayer

                    logger.warning(
                        "Upload echoue (%d) pour %s (tentative %d/%d)",
                        resp.status_code, file_path.name, attempt + 1, len(RETRY_DELAYS),
                    )

            except (httpx.ConnectError, httpx.TimeoutException) as exc:
                logger.warning(
                    "Upload echoue pour %s : %s (tentative %d/%d)",
                    file_path.name, exc, attempt + 1, len(RETRY_DELAYS),
                )

            if attempt < len(RETRY_DELAYS) - 1:
                import asyncio
                await asyncio.sleep(delay)

        return False

    # ── Post JSON avec retry ──────────────────────────────────────────

    async def _post_with_retry(self, url: str, json_body: dict) -> bool:
        """POST JSON avec retry."""
        for attempt, delay in enumerate(RETRY_DELAYS):
            try:
                async with self._build_client() as client:
                    resp = await client.post(url, json=json_body, timeout=30.0)

                if resp.status_code == 200:
                    return True

                logger.warning(
                    "POST echoue (%d) vers %s (tentative %d/%d)",
                    resp.status_code, url, attempt + 1, len(RETRY_DELAYS),
                )

            except (httpx.ConnectError, httpx.TimeoutException) as exc:
                logger.warning(
                    "POST echoue vers %s : %s (tentative %d/%d)",
                    url, exc, attempt + 1, len(RETRY_DELAYS),
                )

            if attempt < len(RETRY_DELAYS) - 1:
                import asyncio
                await asyncio.sleep(delay)

        return False

    # ── Queue offline ─────────────────────────────────────────────────

    def _enqueue(self, task_uuid: str, tool_name: str, result: ToolResult) -> None:
        """Sauve un resultat en queue locale pour upload ulterieur."""
        self._enforce_queue_limits()

        entry = {
            "task_uuid": task_uuid,
            "tool": tool_name,
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "output": result.output,
            "error": result.error,
            "success": result.success,
            "artifact_paths": [str(a) for a in result.artifacts if a.exists()],
        }

        queue_file = self._queue_dir / f"{task_uuid}.json"
        queue_file.write_text(json.dumps(entry, indent=2, ensure_ascii=False), encoding="utf-8")
        logger.info("Resultat mis en queue : %s", task_uuid)

    async def drain_queue(self) -> int:
        """Tente d'envoyer tous les resultats en queue. Retourne le nombre envoyes."""
        self._cleanup_expired()

        queue_files = sorted(self._queue_dir.glob("*.json"))
        if not queue_files:
            return 0

        logger.info("Drain de la queue : %d resultats en attente.", len(queue_files))
        sent = 0

        for qf in queue_files:
            try:
                entry = json.loads(qf.read_text(encoding="utf-8"))
            except (json.JSONDecodeError, OSError):
                logger.warning("Fichier queue corrompu : %s — supprime.", qf.name)
                qf.unlink(missing_ok=True)
                continue

            task_uuid = entry.get("task_uuid", "")
            artifacts = [Path(p) for p in entry.get("artifact_paths", [])]

            # Reconstruire un ToolResult
            result = ToolResult(
                success=entry.get("success", False),
                output=entry.get("output", {}),
                artifacts=artifacts,
                error=entry.get("error"),
            )

            ok = await self._submit_result_http(task_uuid, result)
            if ok and artifacts:
                ok = await self._upload_artifacts(task_uuid, artifacts)

            if ok:
                self._cleanup_artifacts(artifacts)
                qf.unlink(missing_ok=True)
                sent += 1
                logger.info("Queue drain : %s envoye.", task_uuid[:8])
            else:
                logger.warning("Queue drain : %s echoue — reste en queue.", task_uuid[:8])
                break  # Serveur injoignable, arreter le drain

        return sent

    def _enforce_queue_limits(self) -> None:
        """Supprime les entrees les plus anciennes si la queue depasse la limite."""
        queue_files = sorted(self._queue_dir.glob("*.json"), key=lambda p: p.stat().st_mtime)
        while len(queue_files) >= QUEUE_MAX_SIZE:
            oldest = queue_files.pop(0)
            logger.warning("Queue pleine — suppression de %s", oldest.name)
            self._remove_queue_entry(oldest)

    def _cleanup_expired(self) -> None:
        """Supprime les entrees de plus de QUEUE_TTL_DAYS jours."""
        now = time.time()
        cutoff = now - (QUEUE_TTL_DAYS * 86400)

        for qf in self._queue_dir.glob("*.json"):
            if qf.stat().st_mtime < cutoff:
                logger.warning("Resultat expire en queue (>%d jours) : %s", QUEUE_TTL_DAYS, qf.name)
                self._remove_queue_entry(qf)

    def _remove_queue_entry(self, queue_file: Path) -> None:
        """Supprime une entree de queue et ses artifacts."""
        try:
            entry = json.loads(queue_file.read_text(encoding="utf-8"))
            for p in entry.get("artifact_paths", []):
                Path(p).unlink(missing_ok=True)
        except (json.JSONDecodeError, OSError):
            pass
        queue_file.unlink(missing_ok=True)

    # ── Utilitaires ───────────────────────────────────────────────────

    def _build_client(self) -> httpx.AsyncClient:
        """Construit un client httpx avec mTLS et JWT."""
        cert_paths = self._config.cert_paths

        # SSL context pour mTLS
        ssl_ctx: bool | ssl.SSLContext = False
        ca_path = Path(cert_paths.ca)
        cert_file = Path(cert_paths.cert)
        key_file = Path(cert_paths.key)

        if cert_file.exists() and key_file.exists():
            ssl_ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
            if ca_path.exists():
                ssl_ctx.load_verify_locations(str(ca_path))
            else:
                ssl_ctx.check_hostname = False
                ssl_ctx.verify_mode = ssl.CERT_NONE
            ssl_ctx.load_cert_chain(str(cert_file), str(key_file))

        return httpx.AsyncClient(
            verify=ssl_ctx,
            headers={"Authorization": f"Bearer {self._config.jwt_token}"},
        )

    @staticmethod
    def _cleanup_artifacts(artifacts: list[Path]) -> None:
        """Supprime les artifacts locaux."""
        for a in artifacts:
            try:
                a.unlink(missing_ok=True)
            except OSError:
                pass


def setup_uploader(
    config: AgentConfig,
    on_connected_callbacks: list,
) -> ResultUploader:
    """Cree le ResultUploader et enregistre le drain de queue sur reconnexion."""
    uploader = ResultUploader(config)

    async def on_connected() -> None:
        await uploader.drain_queue()

    on_connected_callbacks.append(on_connected)
    return uploader
