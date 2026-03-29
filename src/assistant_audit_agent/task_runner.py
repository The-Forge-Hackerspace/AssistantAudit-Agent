"""Dispatcher d'exécution des tâches reçues du serveur.

Reçoit les messages "new_task" et "task_cancel" via WebSocket, dispatch vers
le bon outil, et remonte les status/résultats au serveur.

Contrainte : UNE SEULE tâche à la fois. Si l'agent est occupé, la tâche
est rejetée avec status "busy".

Format serveur (new_task) :
    {"type": "new_task", "data": {"task_uuid": "...", "tool": "nmap", "parameters": {...}}}

Status renvoyés au serveur :
    task_status  → {"task_uuid": "...", "status": "running"|"rejected"|"busy"|"cancelled", ...}
    task_progress → {"task_uuid": "...", "progress": 0-100, "output_lines": [...]}
    task_result   → {"task_uuid": "...", "result_summary": {...}, "error_message": "..."}
"""

from __future__ import annotations

import asyncio
import logging
import re
import time
from typing import TYPE_CHECKING

from assistant_audit_agent.heartbeat import HeartbeatService
from assistant_audit_agent.tools import ToolBase, ToolResult
from assistant_audit_agent.websocket_client import AgentWebSocketClient

if TYPE_CHECKING:
    from assistant_audit_agent.uploader import ResultUploader

logger = logging.getLogger("task_runner")

# Throttle pour les progress updates (max 1 toutes les 5 secondes)
PROGRESS_THROTTLE_SECONDS = 5.0

# Regex pour filtrer les lignes contenant des credentials
_CREDENTIAL_PATTERN = re.compile(
    r"(?:password|pwd|secret|token)\s*=", re.IGNORECASE
)


class TaskRunner:
    """Dispatcher d'exécution des tâches.

    Une seule tâche à la fois. Les outils sont enregistrés via register_tool().
    """

    def __init__(
        self,
        client: AgentWebSocketClient,
        allowed_tools: list[str],
        heartbeat: HeartbeatService | None = None,
        uploader: ResultUploader | None = None,
    ) -> None:
        self._client = client
        self._allowed_tools = set(allowed_tools)
        self._heartbeat = heartbeat
        self._uploader = uploader
        self._tools: dict[str, ToolBase] = {}
        self._current_task_id: str | None = None
        self._current_tool: ToolBase | None = None
        self._execution_task: asyncio.Task | None = None

    # ── Enregistrement des outils ─────────────────────────────────────

    def register_tool(self, tool: ToolBase) -> None:
        """Enregistre un outil disponible pour exécution."""
        self._tools[tool.name] = tool
        logger.info("Outil enregistré : %s", tool.name)

    # ── Handlers WebSocket ────────────────────────────────────────────

    async def handle_new_task(self, msg_type: str, data: dict) -> None:
        """Handler pour les messages 'new_task' du serveur."""
        task_uuid = data.get("task_uuid", "")
        tool_name = data.get("tool", "")
        parameters = data.get("parameters", {})

        if not task_uuid or not tool_name:
            logger.warning("Message new_task incomplet : %s", data)
            return

        logger.info("Tâche reçue : %s (outil=%s)", task_uuid, tool_name)

        # Vérifier que l'agent n'est pas occupé
        if self._current_task_id is not None:
            logger.warning("Agent occupé — tâche %s rejetée (busy).", task_uuid)
            await self._send_status(task_uuid, "busy")
            return

        # Vérifier que l'outil est autorisé
        if tool_name not in self._allowed_tools:
            logger.warning("Outil '%s' non autorisé — tâche %s rejetée.", tool_name, task_uuid)
            await self._send_status(task_uuid, "rejected", error=f"Outil '{tool_name}' non autorisé.")
            return

        # Vérifier que l'outil est enregistré
        tool = self._tools.get(tool_name)
        if tool is None:
            logger.warning("Outil '%s' non disponible — tâche %s rejetée.", tool_name, task_uuid)
            await self._send_status(task_uuid, "rejected", error=f"Outil '{tool_name}' non disponible sur cet agent.")
            return

        # Lancer l'exécution en arrière-plan
        self._current_task_id = task_uuid
        self._current_tool = tool
        if self._heartbeat is not None:
            self._heartbeat.set_current_task(task_uuid)

        self._execution_task = asyncio.create_task(
            self._execute(task_uuid, tool, parameters)
        )

    async def handle_cancel(self, msg_type: str, data: dict) -> None:
        """Handler pour les messages 'task_cancel' du serveur."""
        task_uuid = data.get("task_uuid", "")

        if not task_uuid:
            return

        if self._current_task_id != task_uuid:
            logger.warning("Cancel pour tâche %s inconnue (en cours: %s).", task_uuid, self._current_task_id)
            return

        logger.info("Annulation de la tâche %s.", task_uuid)

        # Annuler l'outil
        if self._current_tool is not None:
            try:
                await self._current_tool.cancel()
            except Exception:
                logger.exception("Erreur lors de l'annulation de l'outil.")

        # Annuler la tâche asyncio
        if self._execution_task is not None and not self._execution_task.done():
            self._execution_task.cancel()

        await self._send_status(task_uuid, "cancelled")
        self._clear_current_task()

    # ── Exécution ─────────────────────────────────────────────────────

    async def _execute(self, task_uuid: str, tool: ToolBase, parameters: dict) -> None:
        """Exécute un outil et envoie les résultats au serveur."""
        await self._send_status(task_uuid, "running")

        last_progress_time = 0.0
        pending_lines: list[str] = []

        async def on_progress(progress: int, output_lines: list[str]) -> None:
            nonlocal last_progress_time
            pending_lines.extend(output_lines)
            now = time.monotonic()
            if now - last_progress_time >= PROGRESS_THROTTLE_SECONDS:
                last_progress_time = now
                batch = pending_lines.copy()
                pending_lines.clear()
                await self._send_progress(task_uuid, progress, batch)

        try:
            result = await asyncio.wait_for(
                tool.execute(task_uuid, parameters, on_progress=on_progress),
                timeout=tool.default_timeout,
            )
        except asyncio.TimeoutError:
            logger.error("Tâche %s timeout après %ds.", task_uuid, tool.default_timeout)
            try:
                await tool.cancel()
            except Exception:
                pass
            await self._send_status(
                task_uuid, "failed",
                error=f"Timeout après {tool.default_timeout}s.",
            )
            self._clear_current_task()
            return
        except asyncio.CancelledError:
            # Annulation déjà gérée par handle_cancel
            return
        except Exception as exc:
            logger.exception("Tâche %s échouée.", task_uuid)
            await self._send_status(task_uuid, "failed", error=str(exc))
            self._clear_current_task()
            return

        # Flush les lignes restantes
        if pending_lines:
            await self._send_progress(task_uuid, 100 if result.success else 0, pending_lines)
            pending_lines.clear()

        # Envoyer le résultat
        if result.success:
            await self._send_result(task_uuid, result)
            await self._send_status(task_uuid, "completed")
            # Upload via HTTP + gestion artifacts
            if self._uploader is not None:
                await self._uploader.upload_result(task_uuid, tool.name, result)
        else:
            await self._send_status(task_uuid, "failed", error=result.error)

        self._clear_current_task()

    # ── Envoi de messages ─────────────────────────────────────────────

    async def _send_status(
        self, task_uuid: str, status: str, error: str | None = None
    ) -> None:
        """Envoie une mise à jour de status au serveur."""
        data: dict = {"task_uuid": task_uuid, "status": status}
        if error is not None:
            data["error_message"] = error
        await self._client.send("task_status", data)
        logger.info("Status envoyé : %s → %s", task_uuid[:8], status)

    async def _send_progress(
        self, task_uuid: str, progress: int, output_lines: list[str]
    ) -> None:
        """Envoie une mise à jour de progression au serveur.

        Les lignes contenant des credentials (password=, pwd=, secret=, token=)
        sont remplacées par un placeholder avant envoi.
        """
        filtered = [
            "[FILTERED — credential detected]" if _CREDENTIAL_PATTERN.search(line) else line
            for line in output_lines
        ]
        await self._client.send("task_progress", {
            "task_uuid": task_uuid,
            "progress": progress,
            "output_lines": filtered,
        })

    async def _send_result(self, task_uuid: str, result: ToolResult) -> None:
        """Envoie le résultat final au serveur."""
        await self._client.send("task_result", {
            "task_uuid": task_uuid,
            "result_summary": result.output,
            "error_message": result.error,
        })

    # ── État interne ──────────────────────────────────────────────────

    @property
    def is_busy(self) -> bool:
        """True si une tâche est en cours d'exécution."""
        return self._current_task_id is not None

    @property
    def current_task_id(self) -> str | None:
        """UUID de la tâche en cours, ou None."""
        return self._current_task_id

    def _clear_current_task(self) -> None:
        """Libère l'agent pour une nouvelle tâche."""
        self._current_task_id = None
        self._current_tool = None
        self._execution_task = None
        if self._heartbeat is not None:
            self._heartbeat.set_current_task(None)


def setup_task_runner(
    client: AgentWebSocketClient,
    allowed_tools: list[str],
    heartbeat: HeartbeatService | None = None,
    uploader: ResultUploader | None = None,
) -> TaskRunner:
    """Crée le TaskRunner et enregistre les handlers WebSocket."""
    runner = TaskRunner(client, allowed_tools, heartbeat, uploader)
    client.on_message("new_task", runner.handle_new_task)
    client.on_message("task_cancel", runner.handle_cancel)
    return runner
