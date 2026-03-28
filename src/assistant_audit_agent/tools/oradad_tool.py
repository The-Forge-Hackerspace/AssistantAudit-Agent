"""ORADAD (ANSSI) — collecte Active Directory au format TSV.

Le serveur envoie le contenu XML de configuration (config_xml) avec
domaines, credentials et options de collecte. L'agent ecrit le XML
dans un fichier temporaire et lance ORADAD.exe.

Parametres recus du serveur :
    config_xml: str — contenu du fichier config-oradad.xml
    oradad_path: str | None — chemin vers ORADAD.exe (optionnel)

Securite :
    - config_xml ecrit en fichier temporaire, jamais interprete
    - ORADAD.exe lance via asyncio.create_subprocess_exec (pas shell=True)
    - Le fichier config est supprime apres (contient des credentials)
"""

from __future__ import annotations

import asyncio
import logging
import re
import shutil
import tempfile
from pathlib import Path

from assistant_audit_agent.tools import OnProgressCallback, ToolBase, ToolResult

logger = logging.getLogger("oradad")

DEFAULT_ORADAD_PATH = "ORADAD.exe"
_SAFE_PATH_PATTERN = re.compile(r"^[a-zA-Z0-9._:/\\\-\s]+$")


class OradadTool(ToolBase):
    """Outil de collecte AD via ORADAD (ANSSI)."""

    def __init__(self) -> None:
        self._process: asyncio.subprocess.Process | None = None
        self._work_dir: Path | None = None
        self._config_file: Path | None = None

    @property
    def name(self) -> str:
        return "oradad"

    @property
    def default_timeout(self) -> int:
        return 7200  # 2 heures

    async def execute(
        self,
        task_id: str,
        parameters: dict,
        on_progress: OnProgressCallback | None = None,
    ) -> ToolResult:
        """Lance ORADAD avec la configuration fournie par le serveur."""
        config_xml = parameters.get("config_xml", "")
        oradad_path = parameters.get("oradad_path", DEFAULT_ORADAD_PATH)

        if not config_xml:
            return ToolResult(success=False, error="Parametre config_xml manquant.")

        resolved = _resolve_oradad_path(oradad_path)
        if resolved is None:
            return ToolResult(
                success=False,
                error=f"ORADAD.exe introuvable : '{oradad_path}'",
            )

        # Repertoire de travail temporaire
        self._work_dir = Path(tempfile.mkdtemp(prefix=f"oradad_{task_id}_"))
        self._config_file = self._work_dir / "config-oradad.xml"
        self._config_file.write_text(config_xml, encoding="utf-8")

        logger.info("Lancement ORADAD dans %s", self._work_dir)

        try:
            self._process = await asyncio.create_subprocess_exec(
                str(resolved),
                str(self._config_file),
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE,
                cwd=str(self._work_dir),
            )

            output_lines: list[str] = []
            if self._process.stdout is not None:
                while True:
                    line = await self._process.stdout.readline()
                    if not line:
                        break
                    decoded = line.decode("utf-8", errors="replace").rstrip()
                    if decoded:
                        output_lines.append(decoded)
                        if on_progress is not None:
                            await on_progress(0, [decoded])

            await self._process.wait()
            returncode = self._process.returncode

            stderr = ""
            if self._process.stderr is not None:
                stderr = (await self._process.stderr.read()).decode("utf-8", errors="replace")

        except Exception as exc:
            self._cleanup_config()
            return ToolResult(success=False, error=f"Erreur ORADAD : {exc}")
        finally:
            self._process = None
            self._cleanup_config()

        if returncode != 0:
            error_msg = stderr.strip() or f"ORADAD code retour {returncode}"
            return ToolResult(success=False, error=error_msg)

        artifacts = _collect_artifacts(self._work_dir)
        summary = _build_summary(self._work_dir, artifacts)

        return ToolResult(success=True, output=summary, artifacts=artifacts)

    async def cancel(self) -> None:
        """Annule ORADAD en cours."""
        if self._process is not None:
            try:
                self._process.kill()
            except ProcessLookupError:
                pass
            self._process = None
        self._cleanup_config()

    def _cleanup_config(self) -> None:
        """Supprime le fichier config (contient des credentials)."""
        if self._config_file is not None and self._config_file.exists():
            try:
                self._config_file.unlink()
            except OSError:
                pass
            self._config_file = None


def _resolve_oradad_path(oradad_path: str) -> Path | None:
    """Resout le chemin vers ORADAD.exe."""
    if not _SAFE_PATH_PATTERN.match(oradad_path):
        return None
    p = Path(oradad_path)
    if p.is_absolute() and p.exists():
        return p
    found = shutil.which(oradad_path)
    return Path(found) if found else None


def _collect_artifacts(work_dir: Path) -> list[Path]:
    """Collecte les fichiers de sortie ORADAD."""
    artifacts: list[Path] = []
    for pattern in ("*.tar", "*.tar.gz", "*.tsv"):
        artifacts.extend(work_dir.rglob(pattern))
    return artifacts


def _build_summary(work_dir: Path, artifacts: list[Path]) -> dict:
    """Construit un resume des donnees collectees."""
    total_size = sum(a.stat().st_size for a in artifacts if a.exists())
    domains = [d.name for d in work_dir.iterdir() if d.is_dir()]
    return {
        "domains_collected": domains,
        "files_count": len(artifacts),
        "total_size_bytes": total_size,
    }
