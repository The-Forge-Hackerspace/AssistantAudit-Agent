"""Collecte Active Directory via PowerShell.

Lance un script PowerShell qui collecte les informations AD
(comptes, groupes, GPO, politiques de MdP...).

Parametres recus du serveur (ADAuditCreate) :
    target_host: str — IP ou hostname du DC
    target_port: int — port LDAP (389) ou LDAPS (636)
    use_ssl: bool — utiliser LDAPS
    username: str — utilisateur LDAP
    password: str — mot de passe
    domain: str — nom du domaine AD
    auth_method: "ntlm" | "simple"

Securite :
    - Credentials passes via variables d'environnement (pas en CLI)
    - Validation stricte du target_host et domain (regex)
    - Utilise asyncio.create_subprocess_exec (pas de shell)
"""

from __future__ import annotations

import asyncio
import json
import logging
import os
import re
import tempfile
from pathlib import Path

from assistant_audit_agent.tools import OnProgressCallback, ToolBase, ToolResult

logger = logging.getLogger("ad_collector")

_HOSTNAME_PATTERN = re.compile(r"^[a-zA-Z0-9][a-zA-Z0-9._:\-]{0,254}$")
_DOMAIN_PATTERN = re.compile(r"^[a-zA-Z0-9][a-zA-Z0-9.\-]{0,254}$")


class ADCollectorTool(ToolBase):
    """Outil de collecte Active Directory via PowerShell."""

    def __init__(self) -> None:
        self._process: asyncio.subprocess.Process | None = None
        self._output_file: Path | None = None

    @property
    def name(self) -> str:
        return "ad_collector"

    @property
    def default_timeout(self) -> int:
        return 3600  # 1 heure

    async def execute(
        self,
        task_id: str,
        parameters: dict,
        on_progress: OnProgressCallback | None = None,
    ) -> ToolResult:
        """Lance la collecte AD."""
        target_host = parameters.get("target_host", "")
        target_port = parameters.get("target_port", 389)
        use_ssl = parameters.get("use_ssl", False)
        username = parameters.get("username", "")
        password = parameters.get("password", "")
        domain = parameters.get("domain", "")
        auth_method = parameters.get("auth_method", "ntlm")

        # Validation
        if not target_host or not _HOSTNAME_PATTERN.match(target_host):
            return ToolResult(success=False, error=f"target_host invalide : '{target_host}'")

        if not domain or not _DOMAIN_PATTERN.match(domain):
            return ToolResult(success=False, error=f"domain invalide : '{domain}'")

        if not username:
            return ToolResult(success=False, error="username requis.")

        # Fichier de sortie JSON temporaire
        tmp = tempfile.NamedTemporaryFile(
            suffix=".json", prefix=f"ad_{task_id}_", delete=False
        )
        tmp.close()
        self._output_file = Path(tmp.name)

        # Construire le script PowerShell inline
        ps_script = _build_ps_script(
            target_host=target_host,
            target_port=target_port,
            use_ssl=use_ssl,
            domain=domain,
            auth_method=auth_method,
            output_path=str(self._output_file),
        )

        logger.info("Lancement collecte AD sur %s:%d (domaine=%s)", target_host, target_port, domain)

        # Passer les credentials via variables d'environnement
        env = {**os.environ, "AD_USERNAME": username, "AD_PASSWORD": password}

        try:
            self._process = await asyncio.create_subprocess_exec(
                "powershell.exe", "-NoProfile", "-NonInteractive",
                "-ExecutionPolicy", "Bypass", "-Command", ps_script,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE,
                env=env,
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

        except FileNotFoundError:
            self._cleanup()
            return ToolResult(success=False, error="powershell.exe introuvable.")
        except Exception as exc:
            self._cleanup()
            return ToolResult(success=False, error=f"Erreur collecte AD : {exc}")
        finally:
            self._process = None

        if returncode != 0:
            error_msg = stderr.strip() or f"PowerShell code retour {returncode}"
            self._cleanup()
            return ToolResult(success=False, error=error_msg)

        # Lire le JSON de sortie
        result_data = _parse_output(self._output_file)
        artifacts = [self._output_file] if self._output_file.exists() else []
        self._output_file = None

        return ToolResult(success=True, output=result_data, artifacts=artifacts)

    async def cancel(self) -> None:
        """Annule la collecte AD en cours."""
        if self._process is not None:
            try:
                self._process.kill()
            except ProcessLookupError:
                pass
            self._process = None
        self._cleanup()

    def _cleanup(self) -> None:
        """Supprime les fichiers temporaires."""
        if self._output_file is not None:
            try:
                self._output_file.unlink(missing_ok=True)
            except OSError:
                pass
            self._output_file = None


def _build_ps_script(
    target_host: str,
    target_port: int,
    use_ssl: bool,
    domain: str,
    auth_method: str,
    output_path: str,
) -> str:
    """Construit le script PowerShell de collecte AD.

    Les credentials sont lus depuis $env:AD_USERNAME et $env:AD_PASSWORD.
    """
    protocol = "LDAPS" if use_ssl else "LDAP"
    return f"""
$ErrorActionPreference = 'Stop'
$username = $env:AD_USERNAME
$password = $env:AD_PASSWORD
$target = '{target_host}'
$port = {target_port}
$domain = '{domain}'
$protocol = '{protocol}'
$authMethod = '{auth_method}'
$outputPath = '{output_path}'

Write-Host "Connexion a $target`:$port ($protocol)..."
Write-Host "Domaine: $domain"
Write-Host "Methode auth: $authMethod"

# Placeholder - la collecte reelle sera dans un script PS1 dedie
$result = @{{
    domain_name = $domain
    target_host = $target
    target_port = $port
    status = 'completed'
    message = 'Collecte AD placeholder - script PS1 a implementer'
}}

$result | ConvertTo-Json -Depth 10 | Out-File -FilePath $outputPath -Encoding UTF8
Write-Host "Resultats ecrits dans $outputPath"
"""


def _parse_output(output_file: Path) -> dict:
    """Parse le fichier JSON de sortie de la collecte AD."""
    if not output_file.exists():
        return {"error": "Fichier de sortie introuvable."}
    try:
        return json.loads(output_file.read_text(encoding="utf-8-sig"))
    except (json.JSONDecodeError, OSError) as exc:
        return {"error": f"Erreur parsing JSON : {exc}"}
