"""Collecte WinRM — connexion à un serveur Windows et exécution de commandes PowerShell.

Adaptation pour l'agent (mTLS + WebSocket) depuis le collecteur serveur historique.
Exécution synchrone (pywinrm) déléguée à un thread via asyncio.to_thread pour
ne pas bloquer la boucle événementielle de l'agent.

Durcissement TLS (différence avec le collecteur serveur) :
    - Port par défaut : 5986 (HTTPS) au lieu de 5985 (HTTP)
    - use_ssl par défaut : True
    - server_cert_validation par défaut : "validate"
    - Opt-in explicite `insecure_tls=True` requis pour désactiver la validation,
      avec un log d'avertissement à chaque appel (risque MITM).

Paramètres acceptés :
    host: str — IP ou hostname
    username: str — utilisateur (DOMAIN\\user ou user)
    password: str — mot de passe
    port: int = 5986
    use_ssl: bool = True
    transport: str = "ntlm" — ntlm | kerberos | basic | credssp
    insecure_tls: bool = False — désactive la validation du certificat serveur
"""

from __future__ import annotations

import asyncio
import dataclasses
import logging
import re
from dataclasses import dataclass, field

import winrm
import winrm.exceptions

from assistant_audit_agent.tools import OnProgressCallback, ToolBase, ToolResult

logger = logging.getLogger("winrm_collector")

WINRM_TIMEOUT = 60

_HOST_PATTERN = re.compile(r"^[a-zA-Z0-9][a-zA-Z0-9._\-]{0,254}$")
_USERNAME_PATTERN = re.compile(r"^[^\x00-\x1f\"'`;|&$(){}\[\]<>]{1,256}$")
# Modes d'auth pywinrm autorises. "plaintext" est accepte par la lib mais
# transmet le mot de passe en clair sans aucune securite — exclu volontairement.
_TRANSPORT_WHITELIST = frozenset({"ntlm", "kerberos", "basic", "credssp"})


@dataclass
class WinRMCollectResult:
    """Résultat brut de la collecte WinRM."""

    success: bool = False
    error: str | None = None
    hostname: str = ""
    os_info: dict = field(default_factory=dict)
    network: dict = field(default_factory=dict)
    users: dict = field(default_factory=dict)
    services: dict = field(default_factory=dict)
    security: dict = field(default_factory=dict)
    storage: dict = field(default_factory=dict)
    updates: dict = field(default_factory=dict)
    raw_outputs: dict = field(default_factory=dict)


WINDOWS_COMMANDS: dict[str, str] = {
    "hostname": "$env:COMPUTERNAME",
    "os_info": (
        "Get-CimInstance Win32_OperatingSystem | "
        "Select-Object Caption, Version, BuildNumber, OSArchitecture, "
        "LastBootUpTime, InstallDate | Format-List"
    ),
    "domain_info": (
        "(Get-CimInstance Win32_ComputerSystem).Domain + '|' + "
        "(Get-CimInstance Win32_ComputerSystem).PartOfDomain"
    ),
    "installed_updates": (
        "Get-HotFix | Sort-Object InstalledOn -Descending | "
        "Select-Object -First 10 HotFixID, Description, InstalledOn | Format-Table -AutoSize"
    ),
    "last_update_date": (
        "Get-HotFix | Sort-Object InstalledOn -Descending | "
        "Select-Object -First 1 -ExpandProperty InstalledOn"
    ),
    "wsus_config": (
        "try { "
        "(Get-ItemProperty -Path 'HKLM:\\SOFTWARE\\Policies\\Microsoft\\Windows\\WindowsUpdate' "
        "-ErrorAction Stop).WUServer } catch { 'NOT_CONFIGURED' }"
    ),
    "ip_config": (
        "Get-NetIPAddress -AddressFamily IPv4 | "
        "Where-Object { $_.IPAddress -ne '127.0.0.1' } | "
        "Select-Object InterfaceAlias, IPAddress, PrefixLength | Format-Table -AutoSize"
    ),
    "dns_servers": (
        "Get-DnsClientServerAddress -AddressFamily IPv4 | "
        "Where-Object { $_.ServerAddresses } | "
        "Select-Object InterfaceAlias, ServerAddresses | Format-Table -AutoSize"
    ),
    "listening_ports": (
        "Get-NetTCPConnection -State Listen | "
        "Select-Object LocalAddress, LocalPort, OwningProcess | "
        "Sort-Object LocalPort | Format-Table -AutoSize"
    ),
    "firewall_profiles": (
        "Get-NetFirewallProfile | "
        "Select-Object Name, Enabled, DefaultInboundAction, DefaultOutboundAction | "
        "Format-Table -AutoSize"
    ),
    "rdp_enabled": (
        "try { "
        "(Get-ItemProperty -Path 'HKLM:\\SYSTEM\\CurrentControlSet\\Control\\Terminal Server' "
        "-ErrorAction Stop).fDenyTSConnections } catch { 'UNKNOWN' }"
    ),
    "rdp_nla": (
        "try { "
        "(Get-ItemProperty -Path 'HKLM:\\SYSTEM\\CurrentControlSet\\Control\\Terminal Server\\WinStations\\RDP-Tcp' "
        "-ErrorAction Stop).UserAuthentication } catch { 'UNKNOWN' }"
    ),
    "admin_account": (
        "Get-LocalUser | Where-Object { $_.SID -like '*-500' } | "
        "Select-Object Name, Enabled, LastLogon | Format-List"
    ),
    "local_users": (
        "Get-LocalUser | "
        "Select-Object Name, Enabled, LastLogon, PasswordLastSet, PasswordExpires | "
        "Format-Table -AutoSize"
    ),
    "local_admins": (
        "Get-LocalGroupMember -Group 'Administrateurs' -ErrorAction SilentlyContinue | "
        "Select-Object Name, ObjectClass | Format-Table -AutoSize; "
        "Get-LocalGroupMember -Group 'Administrators' -ErrorAction SilentlyContinue | "
        "Select-Object Name, ObjectClass | Format-Table -AutoSize"
    ),
    "password_policy": "net accounts",
    "lockout_policy": "net accounts | Select-String -Pattern 'Lockout|verrouillage'",
    "installed_roles": (
        "try { Get-WindowsFeature | Where-Object Installed | "
        "Select-Object Name, DisplayName | Format-Table -AutoSize } "
        "catch { 'NOT_SERVER_OS' }"
    ),
    "services_running": (
        "Get-Service | Where-Object { $_.Status -eq 'Running' } | "
        "Select-Object Name, DisplayName, StartType | "
        "Sort-Object Name | Format-Table -AutoSize"
    ),
    "event_log_sizes": (
        "Get-WinEvent -ListLog Security, System, Application | "
        "Select-Object LogName, MaximumSizeInBytes, RecordCount, IsEnabled | "
        "Format-Table -AutoSize"
    ),
    "audit_policy": "auditpol /get /category:* 2>&1 | Select-Object -First 40",
    "defender_status": (
        "try { Get-MpComputerStatus | "
        "Select-Object AMRunningMode, AntivirusEnabled, AntispywareEnabled, "
        "RealTimeProtectionEnabled, AntivirusSignatureLastUpdated | Format-List } "
        "catch { 'NOT_AVAILABLE' }"
    ),
    "disk_usage": (
        'Get-CimInstance Win32_LogicalDisk -Filter "DriveType=3" | '
        "Select-Object DeviceID, "
        "@{N='SizeGB';E={[math]::Round($_.Size/1GB,1)}}, "
        "@{N='FreeGB';E={[math]::Round($_.FreeSpace/1GB,1)}}, "
        "@{N='UsedPct';E={[math]::Round(($_.Size-$_.FreeSpace)/$_.Size*100,1)}} | "
        "Format-Table -AutoSize"
    ),
}


def collect_via_winrm(
    host: str,
    username: str,
    password: str,
    port: int = 5986,
    use_ssl: bool = True,
    transport: str = "ntlm",
    insecure_tls: bool = False,
    progress_cb=None,
) -> WinRMCollectResult:
    """Se connecte via WinRM et collecte les informations d'audit Windows.

    Durcissement TLS : defaults HTTPS (5986) + validation certificat.
    Le basculement vers HTTP ou validation "ignore" nécessite un opt-in explicite.
    """
    result = WinRMCollectResult()

    scheme = "https" if use_ssl else "http"
    endpoint = f"{scheme}://{host}:{port}/wsman"

    try:
        logger.info("Connexion WinRM vers %s en tant que %s...", endpoint, username)

        # Par défaut on valide le certificat serveur. `insecure_tls=True` est un
        # opt-in explicite pour les réseaux internes avec certificats auto-signés.
        cert_validation = "validate"
        if not use_ssl:
            logger.warning(
                "WinRM: connexion en clair (HTTP) vers %s — credentials potentiellement exposés",
                host,
            )
        elif insecure_tls:
            logger.warning(
                "WinRM: validation TLS désactivée pour %s (insecure_tls=True) — risque MITM",
                host,
            )
            cert_validation = "ignore"

        session = winrm.Session(
            endpoint,
            auth=(username, password),
            transport=transport,
            server_cert_validation=cert_validation,
            operation_timeout_sec=WINRM_TIMEOUT,
            read_timeout_sec=WINRM_TIMEOUT + 10,
        )

        test = session.run_ps("$env:COMPUTERNAME")
        if test.status_code != 0:
            result.error = (
                f"Échec de connexion WinRM: {test.std_err.decode('utf-8', errors='replace')}"
            )
            return result

        logger.info("Connexion WinRM établie vers %s", host)

        # Encodage de la sortie des commandes natives Windows.
        # Probleme : auditpol/netstat... ecrivent leur sortie dans la code page
        # OEM locale (cp850 sur Windows fr). PowerShell capture ces bytes en
        # supposant cp1252 (ANSI) par defaut et les caracteres accentues sont
        # remplaces par U+FFFD avant meme d'arriver a notre agent.
        # Solution : aligner [Console]::OutputEncoding sur la *vraie* code page
        # OEM du systeme distant. Get-Culture donne la culture, dont le
        # TextInfo.OEMCodePage fournit le numero exact a passer a GetEncoding.
        utf8_prologue = (
            "$OutputEncoding=[System.Text.Encoding]::UTF8; "
            "[Console]::OutputEncoding="
            "[System.Text.Encoding]::GetEncoding("
            "[System.Globalization.CultureInfo]::CurrentCulture.TextInfo.OEMCodePage); "
        )

        def _decode_winrm_bytes(raw: bytes) -> str:
            """Decode la sortie en UTF-8, fallback cp850/cp1252.

            Le prologue PowerShell ne couvre pas tous les natifs Windows
            (auditpol notamment) — leur sortie peut revenir dans la code page
            OEM. On essaie UTF-8 strict d'abord, puis on retombe sur cp850
            (consoles fr OEM) puis cp1252 (ANSI). En dernier recours, decode
            UTF-8 avec replace.
            """
            for enc in ("utf-8", "cp850", "cp1252"):
                try:
                    return raw.decode(enc)
                except UnicodeDecodeError:
                    continue
            return raw.decode("utf-8", errors="replace")

        raw_outputs: dict[str, str] = {}
        total = len(WINDOWS_COMMANDS)
        for idx, (cmd_name, cmd) in enumerate(WINDOWS_COMMANDS.items(), 1):
            try:
                resp = session.run_ps(utf8_prologue + cmd)
                output = _decode_winrm_bytes(resp.std_out).strip()
                if resp.status_code != 0:
                    err = _decode_winrm_bytes(resp.std_err).strip()
                    # On n'ecrase jamais un stdout non vide : PowerShell remote
                    # met du CLIXML sur stderr pour des warnings non-fatals
                    # (SID non resolu, deprecation...) et renvoie un code de
                    # sortie != 0 alors que la commande a reussi. Si on a un
                    # stdout, on le garde et on note l'erreur a part.
                    if not output and err:
                        output = f"ERROR: {err}"
                    elif err:
                        logger.debug("WinRM cmd '%s' stderr (non-fatal): %s", cmd_name, err[:200])
                raw_outputs[cmd_name] = output
            except Exception as exc:
                raw_outputs[cmd_name] = f"ERROR: {exc}"
                logger.debug("Commande '%s' échouée: %s", cmd_name, exc)

            if progress_cb is not None:
                percent = int(idx * 100 / total)
                try:
                    progress_cb(percent, cmd_name)
                except Exception:
                    pass

        result.raw_outputs = raw_outputs
        result.success = True

        _parse_winrm_results(result, raw_outputs)

    except winrm.exceptions.InvalidCredentialsError:
        result.error = "Échec d'authentification WinRM (identifiants invalides)"
        logger.error("Auth WinRM échouée pour %s@%s", username, host)
    except winrm.exceptions.WinRMTransportError as exc:
        result.error = f"Erreur de transport WinRM: {exc}"
        logger.error("Transport WinRM échoué vers %s: %s", host, exc)
    except Exception as exc:
        result.error = f"Erreur de connexion WinRM: {exc}"
        logger.error("Erreur collecte WinRM %s: %s", host, exc)

    return result


def _parse_winrm_results(result: WinRMCollectResult, raw: dict[str, str]) -> None:
    """Parse les sorties brutes des commandes PowerShell en données structurées."""
    result.hostname = raw.get("hostname", "").strip()

    os_raw = raw.get("os_info", "")
    os_info: dict = {"raw": os_raw}
    for line in os_raw.splitlines():
        if ":" in line:
            key, _, val = line.partition(":")
            os_info[key.strip()] = val.strip()

    domain_raw = raw.get("domain_info", "")
    parts = domain_raw.split("|")
    if len(parts) >= 2:
        os_info["domain"] = parts[0].strip()
        os_info["is_domain_joined"] = parts[1].strip().lower() == "true"

    os_info["caption"] = os_info.get("Caption", "Windows Server")
    os_info["version"] = os_info.get("Version", "")
    os_info["build"] = os_info.get("BuildNumber", "")
    result.os_info = os_info

    result.network = {
        "ip_config": raw.get("ip_config", ""),
        "dns_servers": raw.get("dns_servers", ""),
        "listening_ports": raw.get("listening_ports", ""),
    }

    fw_raw = raw.get("firewall_profiles", "")
    fw_profiles: list[dict] = []
    all_enabled = True
    for line in fw_raw.splitlines():
        line = line.strip()
        if not line or line.startswith("-") or line.startswith("Name"):
            continue
        parts = line.split()
        if len(parts) >= 4:
            enabled = parts[1].strip().lower() == "true"
            if not enabled:
                all_enabled = False
            fw_profiles.append(
                {
                    "name": parts[0],
                    "enabled": enabled,
                    "default_inbound": parts[2],
                    "default_outbound": parts[3],
                }
            )

    security: dict = {
        "firewall_profiles": fw_profiles,
        "firewall_all_enabled": all_enabled,
        "firewall_raw": fw_raw,
    }

    rdp_deny = raw.get("rdp_enabled", "UNKNOWN").strip()
    rdp_nla = raw.get("rdp_nla", "UNKNOWN").strip()
    security["rdp_enabled"] = rdp_deny == "0"
    security["rdp_nla_enabled"] = rdp_nla == "1"
    security["rdp_raw_deny"] = rdp_deny
    security["rdp_raw_nla"] = rdp_nla

    admin_raw = raw.get("admin_account", "")
    admin_renamed = True
    for line in admin_raw.splitlines():
        if "Name" in line and ":" in line:
            name = line.split(":")[1].strip().lower()
            if name in ("administrator", "administrateur"):
                admin_renamed = False

    users: dict = {
        "admin_account_raw": admin_raw,
        "admin_renamed": admin_renamed,
        "local_users": raw.get("local_users", ""),
        "local_admins": raw.get("local_admins", ""),
    }

    pwd_policy_raw = raw.get("password_policy", "")
    pwd_policy: dict = {"raw": pwd_policy_raw}
    for line in pwd_policy_raw.splitlines():
        if ":" in line:
            key, _, val = line.partition(":")
            pwd_policy[key.strip()] = val.strip()

    min_length_str = pwd_policy.get(
        "Minimum password length",
        pwd_policy.get("Longueur minimale du mot de passe", "0"),
    )
    try:
        min_length = int(min_length_str.strip())
    except (ValueError, AttributeError):
        min_length = 0
    pwd_policy["min_length_value"] = min_length
    pwd_policy["meets_12_chars"] = min_length >= 12

    users["password_policy"] = pwd_policy

    lockout_threshold_str = pwd_policy.get(
        "Lockout threshold",
        pwd_policy.get("Seuil de verrouillage du compte", "0"),
    )
    try:
        lockout_threshold = int(lockout_threshold_str.strip())
    except (ValueError, AttributeError):
        lockout_threshold = 0
    users["lockout_configured"] = lockout_threshold > 0
    users["lockout_threshold"] = lockout_threshold

    result.users = users
    security["password_policy"] = pwd_policy

    result.services = {
        "installed_roles": raw.get("installed_roles", ""),
        "services_running": raw.get("services_running", ""),
    }

    event_logs_raw = raw.get("event_log_sizes", "")
    logs: list[dict] = []
    for line in event_logs_raw.splitlines():
        line = line.strip()
        if not line or line.startswith("-") or line.startswith("LogName"):
            continue
        parts = line.split()
        if len(parts) >= 4:
            try:
                size_bytes = int(parts[1])
                size_mb = round(size_bytes / (1024 * 1024), 1)
            except (ValueError, IndexError):
                size_mb = 0
            logs.append(
                {
                    "name": parts[0],
                    "max_size_mb": size_mb,
                    "record_count": parts[2] if len(parts) > 2 else "0",
                    "enabled": parts[3] if len(parts) > 3 else "Unknown",
                }
            )

    security["event_logs"] = logs
    security["event_logs_raw"] = event_logs_raw
    security["audit_policy"] = raw.get("audit_policy", "")

    min_log_size = (
        min((log.get("max_size_mb", 0) for log in logs), default=0) if logs else 0
    )
    security["logs_min_100mb"] = min_log_size >= 100

    defender = raw.get("defender_status", "NOT_AVAILABLE")
    av_active = False
    if "NOT_AVAILABLE" not in defender and "ERROR" not in defender:
        av_active = "True" in defender
    security["defender_raw"] = defender
    security["antivirus_active"] = av_active

    result.security = security

    last_update = raw.get("last_update_date", "").strip()
    wsus = raw.get("wsus_config", "NOT_CONFIGURED").strip()
    result.updates = {
        "installed_updates_raw": raw.get("installed_updates", ""),
        "last_update_date": last_update,
        "wsus_configured": wsus != "NOT_CONFIGURED" and "ERROR" not in wsus,
        "wsus_server": wsus if wsus != "NOT_CONFIGURED" else None,
    }

    result.storage = {"disk_usage": raw.get("disk_usage", "")}


class WinRMCollectorTool(ToolBase):
    """Outil de collecte WinRM pour l'agent (pywinrm via thread executor)."""

    def __init__(self) -> None:
        self._cancelled = False

    @property
    def name(self) -> str:
        return "winrm-collect"

    @property
    def default_timeout(self) -> int:
        return 1800  # 30 min

    async def execute(
        self,
        task_id: str,
        parameters: dict,
        on_progress: OnProgressCallback | None = None,
    ) -> ToolResult:
        """Exécute la collecte WinRM sur la cible fournie."""
        self._cancelled = False

        host = parameters.get("host") or parameters.get("target_host") or ""
        username = parameters.get("username", "")
        password = parameters.get("password", "")
        port = int(parameters.get("port", 5986))
        use_ssl = bool(parameters.get("use_ssl", True))
        transport = str(parameters.get("transport", "ntlm")).lower()
        insecure_tls = bool(parameters.get("insecure_tls", False))

        if not host or not _HOST_PATTERN.match(host):
            return ToolResult(success=False, error=f"host invalide : '{host}'")
        if not username or not _USERNAME_PATTERN.match(username):
            return ToolResult(success=False, error="username invalide ou manquant")
        if not password:
            return ToolResult(success=False, error="password requis")
        if not (1 <= port <= 65535):
            return ToolResult(success=False, error=f"port hors plage : {port}")
        if transport not in _TRANSPORT_WHITELIST:
            return ToolResult(
                success=False,
                error=f"transport invalide : '{transport}' (autorisés : {sorted(_TRANSPORT_WHITELIST)})",
            )

        loop = asyncio.get_running_loop()

        def sync_progress(percent: int, label: str) -> None:
            if on_progress is None:
                return
            asyncio.run_coroutine_threadsafe(
                on_progress(percent, [f"WinRM: {label}"]),
                loop,
            )

        if on_progress is not None:
            await on_progress(0, [f"WinRM: connexion à {host}:{port}"])

        result = await asyncio.to_thread(
            collect_via_winrm,
            host,
            username,
            password,
            port,
            use_ssl,
            transport,
            insecure_tls,
            sync_progress,
        )

        if self._cancelled:
            return ToolResult(success=False, error="Annulé")

        if not result.success:
            return ToolResult(
                success=False,
                error=result.error or "Collecte WinRM échouée",
                output=dataclasses.asdict(result),
            )

        if on_progress is not None:
            await on_progress(100, ["WinRM: collecte terminée"])

        return ToolResult(success=True, output=dataclasses.asdict(result))

    async def cancel(self) -> None:
        """Signal d'annulation — la session WinRM en cours ne peut pas être interrompue
        proprement (pywinrm synchrone), mais on marque le flag pour éviter d'émettre
        un résultat après annulation."""
        self._cancelled = True
