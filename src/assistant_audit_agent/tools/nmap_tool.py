"""Exécution de scans nmap en subprocess async.

Paramètres reçus du serveur (via TaskDispatchRequest) :
    target: str — IP, CIDR ou hostname
    scan_type: "discovery" | "port_scan" | "full" | "custom"
    custom_args: str | None — flags nmap additionnels (mode custom)

Sécurité :
    - Validation stricte de target (regex, pas d'injection)
    - Whitelist/blacklist des flags nmap (identique au serveur)
    - JAMAIS de shell=True — utilise asyncio.create_subprocess_exec
"""

from __future__ import annotations

import asyncio
import logging
import re
import tempfile
import xml.etree.ElementTree as ET
from pathlib import Path

from assistant_audit_agent.tools import OnProgressCallback, ToolBase, ToolResult

logger = logging.getLogger("nmap")

# ── Streaming de progression ──────────────────────────────────────────

# Intervalle --stats-every imposé à nmap pour émettre des lignes de progression.
NMAP_STATS_INTERVAL = "5s"

# Nombre max de lignes brutes nmap incluses dans un message task_progress
# (cap sous la limite 16 Ko du serveur).
MAX_OUTPUT_LINES_PER_MESSAGE = 20

# Extrait le pourcentage d'une ligne du type :
#   "Service scan Timing: About 47.50% done; ETC: ..."
_PROGRESS_PATTERN = re.compile(r"(\d+(?:\.\d+)?)%\s*done", re.IGNORECASE)


# ── Validation ────────────────────────────────────────────────────────

_TARGET_PATTERN = re.compile(r"^[a-zA-Z0-9][a-zA-Z0-9._:/\-]{0,254}$")
_PORTS_PATTERN = re.compile(r"^[0-9,\-]+$")
_FLAG_PATTERN = re.compile(r"^-{1,2}[a-zA-Z][a-zA-Z0-9\-]*$")
_VALUE_PATTERN = re.compile(r"^[a-zA-Z0-9_.:/\-,]+$")

ALLOWED_NMAP_FLAGS = {
    "-sS", "-sT", "-sU", "-sA", "-sW", "-sM", "-sN", "-sF", "-sX",
    "-sV", "-sC", "-sn", "-sP", "-sL", "-sO",
    "-p", "--top-ports", "-F",
    "-T0", "-T1", "-T2", "-T3", "-T4", "-T5",
    "--min-rate", "--max-rate", "--min-parallelism", "--max-parallelism",
    "--host-timeout", "--scan-delay", "--max-scan-delay",
    "-O", "-A", "--osscan-guess", "--version-intensity",
    "--version-light", "--version-all",
    "-v", "-vv", "-d", "--reason", "--open",
    "-Pn", "-PS", "-PA", "-PU", "-PY", "-PE", "-PP", "-PM",
    "-PR", "--disable-arp-ping", "--traceroute",
    "-n", "-R", "--dns-servers",
    "--max-retries", "--min-rtt-timeout", "--max-rtt-timeout",
    "--initial-rtt-timeout", "--defeat-rst-ratelimit",
    "-6", "-e",
}

BLOCKED_NMAP_FLAGS = {
    "--script", "--script-args", "--script-args-file", "--script-trace",
    "--script-updatedb", "--script-help",
    "-oN", "-oG", "-oX", "-oA", "-oS",
    "--stylesheet",
    "--interactive", "--exec",
    "--datadir", "--servicedb", "--versiondb",
    "--resume", "--iflist",
    "--send-eth", "--send-ip",
    "--privileged", "--unprivileged",
}

# Mapping scan_type → flags nmap (identique au serveur)
_SCAN_TYPE_FLAGS: dict[str, list[str]] = {
    "discovery": ["-sn"],
    "port_scan": ["-sV", "--top-ports", "1000"],
    "full": ["-sV", "-sC", "-O", "-p-"],
    "custom": [],
}


class NmapTool(ToolBase):
    """Outil d'exécution de scans nmap."""

    def __init__(self) -> None:
        self._process: asyncio.subprocess.Process | None = None
        self._output_file: Path | None = None

    @property
    def name(self) -> str:
        return "nmap"

    @property
    def default_timeout(self) -> int:
        return 3600  # 1 heure

    async def execute(
        self,
        task_id: str,
        parameters: dict,
        on_progress: OnProgressCallback | None = None,
    ) -> ToolResult:
        """Exécute un scan nmap et retourne les résultats structurés."""
        # Vérifier que nmap est installé
        if not await _nmap_available():
            return ToolResult(success=False, error="nmap n'est pas installé ou introuvable dans le PATH.")

        # Extraire et valider les paramètres
        target = parameters.get("target", "")
        scan_type = parameters.get("scan_type", "discovery")
        custom_args = parameters.get("custom_args")

        try:
            args = _build_nmap_args(target, scan_type, custom_args)
        except ValueError as exc:
            return ToolResult(success=False, error=str(exc))

        # Forcer l'émission périodique de lignes de progression par nmap.
        # --stats-every 5s + -v : nmap écrit "XX.XX% done" toutes les 5s.
        if "--stats-every" not in args:
            args.insert(1, "--stats-every")
            args.insert(2, NMAP_STATS_INTERVAL)
        if "-v" not in args and "-vv" not in args:
            args.insert(1, "-v")


        # Fichier de sortie XML temporaire
        tmp = tempfile.NamedTemporaryFile(suffix=".xml", prefix=f"nmap_{task_id}_", delete=False)
        tmp.close()
        self._output_file = Path(tmp.name)

        # Ajouter la sortie XML au fichier
        args.extend(["-oX", str(self._output_file)])

        logger.info("Lancement nmap : %s", " ".join(args))

        try:
            self._process = await asyncio.create_subprocess_exec(
                *args,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE,
            )

            # Lire stdout ET stderr en concurrence : sur Windows, nmap écrit
            # les lignes "Stats: ... XX.XX% done" sur stderr. Lire stdout pendant
            # l'exécution puis stderr après wait() bloquait le parser de progression.
            output_lines: list[str] = []
            stderr_lines: list[str] = []
            last_progress = -1
            pending_buffer: list[str] = []

            async def _drain(stream: asyncio.StreamReader | None, *, is_stderr: bool = False) -> None:
                nonlocal last_progress
                if stream is None:
                    return
                while True:
                    line = await stream.readline()
                    if not line:
                        break
                    decoded = line.decode("utf-8", errors="replace").rstrip()
                    if not decoded:
                        continue
                    output_lines.append(decoded)
                    if is_stderr:
                        stderr_lines.append(decoded)
                    pending_buffer.append(decoded)
                    if len(pending_buffer) > MAX_OUTPUT_LINES_PER_MESSAGE:
                        pending_buffer.pop(0)
                    match = _PROGRESS_PATTERN.search(decoded)
                    if match is None or on_progress is None:
                        continue
                    progress = max(0, min(100, round(float(match.group(1)))))
                    if progress == last_progress:
                        continue
                    last_progress = progress
                    await on_progress(progress, pending_buffer.copy())
                    pending_buffer.clear()

            await asyncio.gather(
                _drain(self._process.stdout),
                _drain(self._process.stderr, is_stderr=True),
            )

            await self._process.wait()
            returncode = self._process.returncode
            stderr = "\n".join(stderr_lines)

        except Exception as exc:
            self._cleanup()
            return ToolResult(success=False, error=f"Erreur d'exécution nmap : {exc}")
        finally:
            self._process = None

        if returncode != 0:
            error_msg = stderr.strip() or f"nmap a retourné le code {returncode}"
            self._cleanup()
            return ToolResult(success=False, error=error_msg)

        # Parser le XML de sortie
        parsed = _parse_nmap_xml(self._output_file)
        artifacts = [self._output_file] if self._output_file.exists() else []
        self._output_file = None

        return ToolResult(
            success=True,
            output=parsed,
            artifacts=artifacts,
        )

    async def cancel(self) -> None:
        """Annule le scan nmap en cours."""
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


# ── Fonctions utilitaires ─────────────────────────────────────────────


async def _nmap_available() -> bool:
    """Vérifie que nmap est installé et accessible."""
    try:
        proc = await asyncio.create_subprocess_exec(
            "nmap", "--version",
            stdout=asyncio.subprocess.DEVNULL,
            stderr=asyncio.subprocess.DEVNULL,
        )
        await proc.wait()
        return proc.returncode == 0
    except FileNotFoundError:
        return False


def _build_nmap_args(target: str, scan_type: str, custom_args: str | None) -> list[str]:
    """Construit la ligne de commande nmap avec validation stricte.

    Raises:
        ValueError: Si target, scan_type ou custom_args sont invalides.
    """
    if not target or not _TARGET_PATTERN.match(target):
        raise ValueError(f"Target nmap invalide : '{target}'")

    if scan_type not in _SCAN_TYPE_FLAGS:
        raise ValueError(f"Type de scan inconnu : '{scan_type}'")

    args = ["nmap"]
    args.extend(_SCAN_TYPE_FLAGS[scan_type])

    if custom_args:
        safe_args = _sanitize_nmap_args(custom_args.split())
        args.extend(safe_args)

    args.append(target)
    return args


def _sanitize_nmap_args(extra_args: list[str]) -> list[str]:
    """Valide et filtre les arguments nmap (whitelist/blacklist).

    Raises:
        ValueError: Si un argument est dangereux ou non autorisé.
    """
    sanitized: list[str] = []

    for arg in extra_args:
        arg = arg.strip()
        if not arg:
            continue

        if arg.startswith("-"):
            flag_base = arg

            # Gérer les flags avec "=" (ex: --script=exploit → --script)
            if "=" in arg:
                flag_base = arg.split("=", 1)[0]
            else:
                for known in sorted(ALLOWED_NMAP_FLAGS, key=len, reverse=True):
                    if arg.startswith(known) and len(arg) > len(known):
                        flag_base = known
                        value_part = arg[len(known):]
                        if not _VALUE_PATTERN.match(value_part):
                            raise ValueError(f"Valeur invalide dans l'argument nmap : '{arg}'")
                        break

            if flag_base in BLOCKED_NMAP_FLAGS:
                raise ValueError(f"Argument nmap interdit : '{flag_base}'")

            if flag_base in ALLOWED_NMAP_FLAGS:
                sanitized.append(arg)
            elif _FLAG_PATTERN.match(arg):
                raise ValueError(f"Argument nmap non autorisé : '{arg}'")
            else:
                raise ValueError(f"Argument nmap invalide : '{arg}'")
        else:
            if not _VALUE_PATTERN.match(arg):
                raise ValueError(f"Valeur d'argument nmap invalide : '{arg}'")
            sanitized.append(arg)

    return sanitized


def _parse_nmap_xml(xml_path: Path) -> dict:
    """Parse le fichier XML de sortie nmap et retourne un dictionnaire structuré."""
    try:
        tree = ET.parse(xml_path)
        root = tree.getroot()
    except Exception as exc:
        return {"error": f"Erreur parsing XML : {exc}", "hosts": []}

    hosts = []
    for host_elem in root.findall("host"):
        status = host_elem.find("status")
        if status is not None and status.get("state") != "up":
            continue

        addr = host_elem.find("address[@addrtype='ipv4']")
        if addr is None:
            addr = host_elem.find("address[@addrtype='ipv6']")
        ip = addr.get("addr", "") if addr is not None else ""

        mac_elem = host_elem.find("address[@addrtype='mac']")
        mac = mac_elem.get("addr", "") if mac_elem is not None else ""
        vendor = mac_elem.get("vendor", "") if mac_elem is not None else ""

        hostname = ""
        hostname_elem = host_elem.find("hostnames/hostname")
        if hostname_elem is not None:
            hostname = hostname_elem.get("name", "")

        os_guess = ""
        osmatch = host_elem.find("os/osmatch")
        if osmatch is not None:
            os_guess = osmatch.get("name", "")

        ports = []
        for port_elem in host_elem.findall("ports/port"):
            state_elem = port_elem.find("state")
            service_elem = port_elem.find("service")
            ports.append({
                "port": int(port_elem.get("portid", 0)),
                "protocol": port_elem.get("protocol", "tcp"),
                "state": state_elem.get("state", "") if state_elem is not None else "",
                "service": service_elem.get("name", "") if service_elem is not None else "",
                "product": service_elem.get("product", "") if service_elem is not None else "",
                "version": service_elem.get("version", "") if service_elem is not None else "",
            })

        hosts.append({
            "ip": ip,
            "hostname": hostname,
            "mac": mac,
            "vendor": vendor,
            "os": os_guess,
            "ports": ports,
        })

    scan_stats: dict = {}
    runstats = root.find("runstats/finished")
    if runstats is not None:
        scan_stats["elapsed"] = runstats.get("elapsed", "0")
        scan_stats["exit"] = runstats.get("exit", "")

    hosts_summary = root.find("runstats/hosts")
    if hosts_summary is not None:
        scan_stats["hosts_up"] = int(hosts_summary.get("up", 0))
        scan_stats["hosts_down"] = int(hosts_summary.get("down", 0))
        scan_stats["hosts_total"] = int(hosts_summary.get("total", 0))

    return {"hosts": hosts, "scan_stats": scan_stats}
