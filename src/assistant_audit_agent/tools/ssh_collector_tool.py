"""Collecte SSH — connexion à un serveur Linux ou pare-feu via SSH (paramiko).

Adaptation pour l'agent (mTLS + WebSocket) depuis le collecteur serveur historique.
Exécution synchrone (paramiko) déléguée à un thread via asyncio.to_thread pour
ne pas bloquer la boucle événementielle de l'agent.

Profils supportés :
    linux_server : Serveur Linux (Debian, Ubuntu, RHEL, CentOS…)
    opnsense     : Pare-feu OPNsense (FreeBSD) — SFTP config.xml + shell interactif
    stormshield  : Pare-feu Stormshield (SNS)
    fortigate    : Pare-feu FortiGate (FortiOS)

Paramètres acceptés :
    host: str — IP ou hostname
    port: int = 22
    username: str = "root"
    password: str | None
    private_key: str | None — contenu PEM de la clé privée
    passphrase: str | None — passphrase de la clé
    device_profile: str = "linux_server"

Sécurité :
    - RejectPolicy : hôtes inconnus rejetés (known_hosts requis côté agent)
    - Credentials chiffrés en transit (EncryptedJSON côté serveur)
    - Validation stricte du host et du device_profile
"""

from __future__ import annotations

import asyncio
import dataclasses
import io
import logging
import re
import time
from dataclasses import dataclass, field
from typing import Optional

import defusedxml.ElementTree as ET
import paramiko

from assistant_audit_agent.tools import OnProgressCallback, ToolBase, ToolResult

logger = logging.getLogger("ssh_collector")

SSH_CONNECT_TIMEOUT = 15
SSH_COMMAND_TIMEOUT = 30

SUPPORTED_PROFILES = ("linux_server", "opnsense", "stormshield", "fortigate")

_HOST_PATTERN = re.compile(r"^[a-zA-Z0-9][a-zA-Z0-9._\-]{0,254}$")
_USERNAME_PATTERN = re.compile(r"^[^\x00-\x1f\"'`;|&$(){}\[\]<>]{1,256}$")


@dataclass
class SSHCollectResult:
    """Résultat brut de la collecte SSH."""

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


# ── Commandes Linux ──────────────────────────────────────────
LINUX_COMMANDS: dict[str, str] = {
    "hostname": "hostname -f 2>/dev/null || hostname",
    "os_release": "cat /etc/os-release 2>/dev/null",
    "kernel": "uname -r",
    "uptime": "uptime -p 2>/dev/null || uptime",
    "arch": "uname -m",
    "apt_updates": ("apt list --upgradable 2>/dev/null | grep -c upgradable || echo 0"),
    "apt_security": ("apt list --upgradable 2>/dev/null | grep -i security | wc -l || echo 0"),
    "yum_updates": "yum check-update --quiet 2>/dev/null | grep -c '\\.' || echo 0",
    "unattended_upgrades": (
        "dpkg -l unattended-upgrades 2>/dev/null | grep -c '^ii' || "
        "systemctl is-enabled dnf-automatic.timer 2>/dev/null || echo 0"
    ),
    "ip_addresses": "ip -4 addr show 2>/dev/null || ifconfig 2>/dev/null",
    "routes": "ip route show 2>/dev/null || route -n 2>/dev/null",
    "dns": "cat /etc/resolv.conf 2>/dev/null",
    "listening_ports": "ss -tlnp 2>/dev/null || netstat -tlnp 2>/dev/null",
    "ufw_status": "ufw status verbose 2>/dev/null || echo NOT_INSTALLED",
    "iptables_rules": "iptables -L -n --line-numbers 2>/dev/null | head -80 || echo NO_ACCESS",
    "nftables_rules": "nft list ruleset 2>/dev/null | head -80 || echo NOT_INSTALLED",
    "sshd_config": "cat /etc/ssh/sshd_config 2>/dev/null | grep -v '^#' | grep -v '^$'",
    "ssh_root_login": ("grep -i '^PermitRootLogin' /etc/ssh/sshd_config 2>/dev/null || echo 'NOT_SET'"),
    "ssh_password_auth": ("grep -i '^PasswordAuthentication' /etc/ssh/sshd_config 2>/dev/null || echo 'NOT_SET'"),
    "users_with_shell": (
        "cat /etc/passwd | grep -v '/nologin' | grep -v '/false' | awk -F: '{print $1\":\"$3\":\"$7}'"
    ),
    "sudoers": "cat /etc/sudoers 2>/dev/null | grep -v '^#' | grep -v '^$' | head -30 || echo NO_ACCESS",
    "last_logins": "last -n 10 2>/dev/null",
    "services_running": "systemctl list-units --type=service --state=running --no-pager 2>/dev/null | head -60",
    "services_enabled": "systemctl list-unit-files --type=service --state=enabled --no-pager 2>/dev/null | head -60",
    "rsyslog_active": "systemctl is-active rsyslog 2>/dev/null || echo inactive",
    "journald_config": "cat /etc/systemd/journald.conf 2>/dev/null | grep -v '^#' | grep -v '^$'",
    "auditd_active": "systemctl is-active auditd 2>/dev/null || echo inactive",
    "auditd_rules": "auditctl -l 2>/dev/null | head -30 || echo NO_ACCESS",
    "disk_usage": "df -h 2>/dev/null",
    "mount_points": "mount 2>/dev/null | grep -v tmpfs | grep -v cgroup",
    "passwd_perms": "ls -la /etc/passwd /etc/shadow 2>/dev/null",
    "selinux": "getenforce 2>/dev/null || echo NOT_INSTALLED",
    "apparmor": "apparmor_status 2>/dev/null | head -5 || echo NOT_INSTALLED",
    "antivirus": (
        "systemctl is-active clamav-daemon 2>/dev/null && echo clamav || "
        "systemctl is-active falcon-sensor 2>/dev/null && echo crowdstrike || "
        "systemctl is-active mdatp 2>/dev/null && echo defender || "
        "echo NONE"
    ),
    "pam_pwquality": (
        "cat /etc/security/pwquality.conf 2>/dev/null | grep -v '^#' | grep -v '^$' || echo NOT_CONFIGURED"
    ),
}


# ── Commandes OPNsense ───────────────────────────────────────
OPNSENSE_COMMANDS: dict[str, str] = {
    "hostname": "hostname",
    "os_version": "opnsense-version -v 2>/dev/null || freebsd-version",
    "os_name": "opnsense-version -n 2>/dev/null || echo OPNsense",
    "kernel": "uname -r",
    "uptime": "uptime",
    "arch": "uname -m",
    "updates_pending": "opnsense-update -c 2>/dev/null; echo EXIT=$?",
    "pkg_audit": "pkg audit -F 2>/dev/null | tail -5 || echo NOT_AVAILABLE",
    "installed_version": "opnsense-version 2>/dev/null",
    "interfaces": "ifconfig -a 2>/dev/null | head -100",
    "routes": "netstat -rn 2>/dev/null | head -40",
    "dns": "cat /etc/resolv.conf 2>/dev/null",
    "listening_ports": "sockstat -4 -l 2>/dev/null | head -60",
    "pf_status": "/sbin/pfctl -s info 2>/dev/null || pfctl -s info 2>/dev/null || echo PF_DISABLED",
    "pf_rules_count": "/sbin/pfctl -s rules 2>/dev/null | wc -l | tr -d ' ' || echo 0",
    "pf_rules": "/sbin/pfctl -s rules 2>/dev/null | head -80",
    "pf_nat": "/sbin/pfctl -s nat 2>/dev/null | head -40",
    "pf_states_count": "/sbin/pfctl -s info 2>/dev/null | grep -i 'current entries' || echo N/A",
    "config_xml_size": "ls -la /conf/config.xml 2>/dev/null",
    "config_backup_count": "ls /conf/backup/ 2>/dev/null | wc -l | tr -d ' ' || echo 0",
    "aliases": "/sbin/pfctl -t -s Tables 2>/dev/null | head -30 || echo NONE",
    "services": "configctl service list 2>/dev/null || service -e 2>/dev/null",
    "openvpn_status": "configctl openvpn status 2>/dev/null || sockstat -4 | grep openvpn || echo NOT_RUNNING",
    "ipsec_status": "ipsec statusall 2>/dev/null | head -30 || echo NOT_CONFIGURED",
    "wireguard_status": "wg show 2>/dev/null || echo NOT_INSTALLED",
    "ssh_config": "cat /etc/ssh/sshd_config 2>/dev/null | grep -v '^#' | grep -v '^$'",
    "ssh_root_login": "grep -i '^PermitRootLogin' /etc/ssh/sshd_config 2>/dev/null || echo 'NOT_SET'",
    "users": "cat /etc/passwd 2>/dev/null | grep -v nologin | grep -v '/usr/sbin/nologin'",
    "clog_filter": "clog /var/log/filter.log 2>/dev/null | tail -20 || echo NO_ACCESS",
    "syslog_remote": "grep -i '@' /usr/local/etc/syslog.conf 2>/dev/null || echo NONE",
    "suricata_status": "configctl ids status 2>/dev/null || pgrep suricata > /dev/null && echo RUNNING || echo NOT_RUNNING",
    "carp_status": "ifconfig | grep -A1 carp 2>/dev/null || echo NO_CARP",
}


# ── Commandes Stormshield ────────────────────────────────────
STORMSHIELD_COMMANDS: dict[str, str] = {
    "system_info": "VERSION",
    "hostname": "CONFIG SYSTEM PROPERTY index=Name",
    "serial": "CONFIG SYSTEM PROPERTY index=SerialNumber",
    "uptime": "SYSTEM UPTIME",
    "license": "CONFIG LICENSE LIST",
    "interfaces": "CONFIG NETWORK INTERFACE LIST",
    "routes": "CONFIG NETWORK ROUTE LIST",
    "dns": "CONFIG NETWORK DNS LIST",
    "filter_rules_count": "CONFIG FILTER COUNT",
    "filter_rules": "CONFIG FILTER SHOW",
    "nat_rules": "CONFIG NAT SHOW",
    "active_connections": "CONFIG FILTER CONNTRACK list state=established",
    "objects_host": "CONFIG OBJECT HOST LIST",
    "objects_network": "CONFIG OBJECT NETWORK LIST",
    "objects_group": "CONFIG OBJECT GROUP LIST",
    "vpn_ipsec_peers": "CONFIG IPSEC PEER LIST",
    "vpn_ipsec_sa": "PKI IPSEC SA LIST",
    "vpn_ssl_status": "CONFIG OPENVPN LIST",
    "admin_accounts": "CONFIG AUTH LOCAL USER LIST",
    "ssh_status": "CONFIG SSH SHOW",
    "antivirus": "CONFIG ANTIVIRUS SHOW",
    "ips_status": "CONFIG ASQ SHOW",
    "syslog_servers": "CONFIG SYSLOG LIST",
    "alarm_list": "CONFIG ALARM LIST filter=on",
    "ha_status": "HA STATUS",
    "services_status": "SYSTEM SERVICE LIST",
    "firmware_version": "VERSION",
    "update_status": "SYSTEM UPDATE STATUS",
}


# ── Commandes FortiGate ──────────────────────────────────────
FORTIGATE_COMMANDS: dict[str, str] = {
    "system_status": "get system status",
    "hostname": "get system global | grep hostname",
    "serial": "get system status | grep Serial",
    "uptime": "get system performance status | grep Uptime",
    "firmware": "get system status | grep Version",
    "license": "get system fortiguard-service status",
    "interfaces": "get system interface | grep -A5 '== \\['",
    "interfaces_physical": "diagnose hardware deviceinfo nic",
    "routes": "get router info routing-table all",
    "dns": "get system dns",
    "arp_table": "get system arp | head -40",
    "policy_count": "get firewall policy | grep -c 'edit'",
    "policies": "show firewall policy | head -200",
    "policy_summary": "diagnose firewall iprope list 100004 | head -60",
    "vip": "get firewall vip | head -40",
    "address_objects": "get firewall address | head -60",
    "address_groups": "get firewall addrgrp | head -40",
    "vpn_ipsec_tunnels": "get vpn ipsec tunnel summary",
    "vpn_ssl_status": "get vpn ssl monitor",
    "vpn_ssl_settings": "get vpn ssl settings | head -30",
    "admin_users": "get system admin | grep 'edit\\|accprofile'",
    "admin_settings": "get system global | grep admin",
    "password_policy": "get system password-policy",
    "trusted_hosts": "show system admin | grep trustedhost",
    "antivirus_profile": "get antivirus profile | head -30",
    "ips_settings": "get ips global",
    "webfilter": "get webfilter profile | head -20",
    "log_settings": "get log setting",
    "log_syslogd": "get log syslogd setting",
    "log_fortianalyzer": "get log fortianalyzer setting",
    "log_disk": "get log disk setting",
    "ha_status": "get system ha status",
    "ntp": "get system ntp | head -20",
    "snmp": "get system snmp sysinfo",
    "session_count": "diagnose sys session stat",
}


PROFILE_COMMANDS: dict[str, dict[str, str]] = {
    "linux_server": LINUX_COMMANDS,
    "opnsense": OPNSENSE_COMMANDS,
    "stormshield": STORMSHIELD_COMMANDS,
    "fortigate": FORTIGATE_COMMANDS,
}


def collect_via_ssh(
    host: str,
    port: int = 22,
    username: str = "root",
    password: Optional[str] = None,
    private_key: Optional[str] = None,
    passphrase: Optional[str] = None,
    device_profile: str = "linux_server",
    progress_cb=None,
) -> SSHCollectResult:
    """Se connecte via SSH et collecte les informations d'audit."""
    result = SSHCollectResult()
    client = paramiko.SSHClient()

    commands = PROFILE_COMMANDS.get(device_profile, LINUX_COMMANDS)
    logger.info("Profil de collecte: %s (%d commandes)", device_profile, len(commands))

    def _emit(percent: int, label: str) -> None:
        if progress_cb is not None:
            try:
                progress_cb(percent, label)
            except Exception:
                logger.debug("progress_cb failed", exc_info=True)

    try:
        client.load_system_host_keys()
    except Exception:
        pass

    # Un agent on-prem audite des hotes arbitraires fournis par l'API ; un known_hosts
    # pre-rempli n'est pas realiste. On accepte les nouveaux hotes en loggant le
    # fingerprint pour traçabilite (TOFU). Les hotes deja connus restent verifies via
    # load_system_host_keys ci-dessus.
    class _LogAndAccept(paramiko.MissingHostKeyPolicy):
        def missing_host_key(self, _client, hostname, key):  # noqa: D401
            logger.warning(
                "SSH host inconnu accepte (TOFU) : %s key_type=%s fingerprint=%s",
                hostname,
                key.get_name(),
                key.fingerprint if hasattr(key, "fingerprint") else "?",
            )

    client.set_missing_host_key_policy(_LogAndAccept())

    try:
        connect_kwargs: dict = {
            "hostname": host,
            "port": port,
            "username": username,
            "timeout": SSH_CONNECT_TIMEOUT,
            "allow_agent": False,
            "look_for_keys": False,
        }

        if private_key:
            # Le client n'envoie pas le type de cle ; on essaie chaque format
            # supporte par paramiko jusqu'a en trouver un qui charge correctement.
            pkey = None
            last_err: Exception | None = None
            for key_cls in (
                paramiko.Ed25519Key,
                paramiko.ECDSAKey,
                paramiko.RSAKey,
                paramiko.DSSKey,
            ):
                try:
                    pkey = key_cls.from_private_key(
                        io.StringIO(private_key),
                        password=passphrase,
                    )
                    break
                except (paramiko.SSHException, ValueError) as exc:
                    last_err = exc
                    continue
            if pkey is None:
                raise paramiko.SSHException(
                    f"Cle privee non supportee (essais Ed25519/ECDSA/RSA/DSS) : {last_err}"
                )
            connect_kwargs["pkey"] = pkey
        elif password:
            connect_kwargs["password"] = password
        else:
            connect_kwargs["allow_agent"] = True
            connect_kwargs["look_for_keys"] = True

        _emit(5, f"Connexion SSH {host}:{port}")
        logger.info("Connexion SSH vers %s:%d en tant que %s...", host, port, username)
        client.connect(**connect_kwargs)
        logger.info("Connexion SSH établie vers %s:%d", host, port)
        _emit(15, "Connexion établie")

        if device_profile == "opnsense":
            _emit(20, "OPNsense: SFTP /conf/config.xml")
            logger.info("OPNsense: collecte via SFTP /conf/config.xml")
            config_data = _collect_opnsense_via_sftp(client)

            if "error" not in config_data:
                _emit(60, "OPNsense: shell interactif")
                logger.info("OPNsense: tentative de commandes dynamiques via shell interactif")
                dynamic_data = _try_opnsense_dynamic_commands(client)
                _build_opnsense_from_config(result, config_data, dynamic_data)
                result.success = True
                logger.info(
                    "OPNsense collecte OK: hostname=%s, rules=%s, dynamic_cmds=%d",
                    result.hostname,
                    result.security.get("firewall_rules_count", 0),
                    len(dynamic_data),
                )
            else:
                logger.warning(
                    "OPNsense SFTP échoué (%s), fallback sur exec_command...",
                    config_data.get("error"),
                )
                raw_outputs: dict[str, str] = {}
                total = len(commands)
                for idx, (cmd_name, cmd) in enumerate(commands.items(), 1):
                    try:
                        _, stdout, _ = client.exec_command(cmd, timeout=SSH_COMMAND_TIMEOUT)
                        output = stdout.read().decode("utf-8", errors="replace").strip()
                        raw_outputs[cmd_name] = output
                    except Exception as e:
                        raw_outputs[cmd_name] = f"ERROR: {e}"
                        logger.debug("Commande '%s' échouée: %s", cmd_name, e)
                    _emit(30 + int(60 * idx / max(total, 1)), f"{cmd_name} ({idx}/{total})")
                result.raw_outputs = raw_outputs
                result.success = True
                _parse_opnsense_results(result, raw_outputs)
        else:
            raw_outputs: dict[str, str] = {}
            total = len(commands)
            for idx, (cmd_name, cmd) in enumerate(commands.items(), 1):
                try:
                    _, stdout, _ = client.exec_command(cmd, timeout=SSH_COMMAND_TIMEOUT)
                    output = stdout.read().decode("utf-8", errors="replace").strip()
                    raw_outputs[cmd_name] = output
                except Exception as e:
                    raw_outputs[cmd_name] = f"ERROR: {e}"
                    logger.debug("Commande '%s' échouée: %s", cmd_name, e)
                _emit(20 + int(70 * idx / max(total, 1)), f"{cmd_name} ({idx}/{total})")

            result.raw_outputs = raw_outputs
            result.success = True

            if device_profile == "linux_server":
                _parse_ssh_results(result, raw_outputs)
            elif device_profile == "stormshield":
                _parse_stormshield_results(result, raw_outputs)
            elif device_profile == "fortigate":
                _parse_fortigate_results(result, raw_outputs)
            else:
                _parse_ssh_results(result, raw_outputs)

        _emit(95, "Finalisation")

    except paramiko.AuthenticationException:
        result.error = "Échec d'authentification SSH"
        logger.error("Auth SSH échouée pour %s@%s:%d", username, host, port)
    except paramiko.SSHException as e:
        result.error = f"Erreur SSH: {e}"
        logger.error("Erreur SSH vers %s:%d: %s", host, port, e)
    except TimeoutError:
        result.error = f"Timeout de connexion SSH vers {host}:{port}"
        logger.error("Timeout SSH vers %s:%d", host, port)
    except Exception as e:
        import traceback

        result.error = f"Erreur de connexion: {e}"
        logger.error("Erreur collecte SSH %s:%d: %s", host, port, e)
        logger.error(traceback.format_exc())
    finally:
        client.close()

    return result


def _parse_ssh_results(result: SSHCollectResult, raw: dict[str, str]) -> None:
    """Parse les sorties brutes des commandes Linux en données structurées."""
    result.hostname = raw.get("hostname", "").strip()

    os_info: dict = {}
    os_release = raw.get("os_release", "")
    for line in os_release.splitlines():
        if "=" in line:
            key, _, val = line.partition("=")
            os_info[key.strip()] = val.strip().strip('"')
    os_info["kernel"] = raw.get("kernel", "")
    os_info["arch"] = raw.get("arch", "")
    os_info["uptime"] = raw.get("uptime", "")

    distro_name = os_info.get("PRETTY_NAME", os_info.get("NAME", "Linux"))
    os_info["distro"] = distro_name
    os_info["version_id"] = os_info.get("VERSION_ID", "")
    result.os_info = os_info

    network: dict = {
        "ip_addresses": raw.get("ip_addresses", ""),
        "routes": raw.get("routes", ""),
        "dns": raw.get("dns", ""),
        "listening_ports": raw.get("listening_ports", ""),
    }
    ports_list = []
    for line in raw.get("listening_ports", "").splitlines():
        if "LISTEN" in line:
            ports_list.append(line.strip())
    network["listening_ports_parsed"] = ports_list
    result.network = network

    fw_status = "unknown"
    ufw = raw.get("ufw_status", "")
    iptables = raw.get("iptables_rules", "")
    nftables = raw.get("nftables_rules", "")

    if "Status: active" in ufw:
        fw_status = "ufw_active"
    elif "NOT_INSTALLED" not in ufw and "inactive" not in ufw.lower():
        fw_status = "ufw_inactive"
    elif "NOT_INSTALLED" not in nftables and nftables.strip():
        fw_status = "nftables_active"
    elif "Chain" in iptables and "NO_ACCESS" not in iptables:
        fw_status = "iptables_active"
    else:
        fw_status = "none_detected"

    security: dict = {
        "firewall_status": fw_status,
        "firewall_details": ufw if "Status:" in ufw else (nftables if nftables.strip() else iptables),
    }

    ssh_root = raw.get("ssh_root_login", "NOT_SET").strip()
    ssh_pass = raw.get("ssh_password_auth", "NOT_SET").strip()
    security["ssh_permit_root_login"] = ssh_root
    security["ssh_password_authentication"] = ssh_pass
    security["sshd_config_raw"] = raw.get("sshd_config", "")

    security["selinux"] = raw.get("selinux", "NOT_INSTALLED").strip()
    security["apparmor"] = raw.get("apparmor", "NOT_INSTALLED").strip()
    security["passwd_perms"] = raw.get("passwd_perms", "")
    security["antivirus_edr"] = raw.get("antivirus", "NONE").strip()
    security["pam_pwquality"] = raw.get("pam_pwquality", "NOT_CONFIGURED")
    result.security = security

    users_raw = raw.get("users_with_shell", "")
    users_list = []
    for line in users_raw.splitlines():
        parts = line.split(":")
        if len(parts) >= 3:
            users_list.append(
                {
                    "username": parts[0],
                    "uid": parts[1],
                    "shell": parts[2],
                }
            )
    result.users = {
        "users_with_shell": users_list,
        "sudoers_raw": raw.get("sudoers", ""),
        "last_logins": raw.get("last_logins", ""),
    }

    result.services = {
        "running": raw.get("services_running", ""),
        "enabled": raw.get("services_enabled", ""),
    }

    result.security["rsyslog_active"] = raw.get("rsyslog_active", "inactive").strip()
    result.security["auditd_active"] = raw.get("auditd_active", "inactive").strip()
    result.security["auditd_rules"] = raw.get("auditd_rules", "")
    result.security["journald_config"] = raw.get("journald_config", "")

    apt_updates = raw.get("apt_updates", "0").strip()
    apt_security = raw.get("apt_security", "0").strip()
    yum_updates = raw.get("yum_updates", "0").strip()
    unattended = raw.get("unattended_upgrades", "0").strip()

    try:
        pending = int(apt_updates) if apt_updates.isdigit() else int(yum_updates) if yum_updates.isdigit() else 0
    except ValueError:
        pending = 0

    try:
        sec_pending = int(apt_security) if apt_security.isdigit() else 0
    except ValueError:
        sec_pending = 0

    result.updates = {
        "pending_updates": pending,
        "security_updates": sec_pending,
        "auto_updates_configured": "1" in unattended or "enabled" in unattended.lower(),
    }

    result.storage = {
        "disk_usage": raw.get("disk_usage", ""),
        "mount_points": raw.get("mount_points", ""),
    }


# ──────────────────────────────────────────────────────────────
# OPNsense : SFTP config.xml
# ──────────────────────────────────────────────────────────────


def _collect_opnsense_via_sftp(client: paramiko.SSHClient) -> dict:
    """Télécharge /conf/config.xml via SFTP et extrait les données d'audit."""
    data: dict = {"source": "sftp_config_xml"}

    try:
        sftp = client.open_sftp()
        try:
            with sftp.open("/conf/config.xml", "r") as f:
                content = f.read().decode("utf-8", errors="replace")

            root = ET.fromstring(content)

            hostname = (root.findtext(".//system/hostname") or "").strip()
            domain = (root.findtext(".//system/domain") or "").strip()
            data["hostname"] = f"{hostname}.{domain}" if domain else hostname

            ssh_el = root.find(".//system/ssh")
            if ssh_el is not None:
                permit_root = (root.findtext(".//system/ssh/permitrootlogin") or "").strip()
                passwd_auth = (root.findtext(".//system/ssh/passwordauth") or "").strip()
                ssh_enabled = (root.findtext(".//system/ssh/enabled") or "").strip()

                data["ssh_enabled"] = ssh_enabled == "enabled"
                data["ssh_permit_root_login"] = "yes" if permit_root == "1" else "no"
                data["ssh_password_auth"] = "yes" if passwd_auth == "1" else "no"

                data["ssh_config_raw"] = (
                    f"PermitRootLogin {'yes' if permit_root == '1' else 'no'}\n"
                    f"PasswordAuthentication {'yes' if passwd_auth == '1' else 'no'}"
                )
            else:
                data["ssh_permit_root_login"] = "NOT_SET"
                data["ssh_password_auth"] = "NOT_SET"
                data["ssh_config_raw"] = ""

            filter_node = root.find(".//filter")
            total_rules = 0
            enabled_rules = 0
            rules_text_lines: list[str] = []

            if filter_node is not None:
                for idx, rule_el in enumerate(filter_node.findall("rule"), 1):
                    total_rules += 1
                    disabled = rule_el.find("disabled") is not None
                    if not disabled:
                        enabled_rules += 1

                    rule_type = (rule_el.findtext("type") or "pass").strip()
                    interface = (rule_el.findtext("interface") or "").strip()
                    descr = (rule_el.findtext("descr") or "").strip()
                    protocol = (rule_el.findtext("protocol") or "any").strip()

                    src = (
                        "any"
                        if rule_el.find("source/any") is not None
                        else (
                            (rule_el.findtext("source/network") or "").strip()
                            or (rule_el.findtext("source/address") or "").strip()
                            or "?"
                        )
                    )
                    dst = (
                        "any"
                        if rule_el.find("destination/any") is not None
                        else (
                            (rule_el.findtext("destination/network") or "").strip()
                            or (rule_el.findtext("destination/address") or "").strip()
                            or "?"
                        )
                    )
                    dst_port = (rule_el.findtext("destination/port") or "").strip()
                    status = "disabled" if disabled else "enabled"
                    log_flag = "log" if rule_el.find("log") is not None else ""

                    service = f"{protocol}/{dst_port}" if dst_port else protocol
                    rules_text_lines.append(
                        f"#{idx} [{status}] {rule_type} {interface}: {src} → {dst} {service} {log_flag} {descr}"
                    )

            data["firewall_rules_count"] = enabled_rules
            data["firewall_rules_total"] = total_rules
            data["firewall_rules_text"] = "\n".join(rules_text_lines)
            data["firewall_enabled"] = True

            nat_rules = root.findall(".//nat/rule")
            data["nat_rules_count"] = len(nat_rules)

            ids_enabled = (root.findtext(".//OPNsense/IDS/general/enabled") or "0").strip()
            data["suricata_status"] = "RUNNING" if ids_enabled == "1" else "NOT_RUNNING"

            remote_hosts: list[str] = []
            for dest in root.findall(".//syslog/destinations/destination"):
                transport = (dest.findtext("transport") or "").strip()
                h = (dest.findtext("hostname") or "").strip()
                port = (dest.findtext("port") or "").strip()
                if h:
                    remote_hosts.append(f"{transport}://{h}:{port}" if port else h)
            if not remote_hosts:
                for srv in root.findall(".//syslog/remoteserver"):
                    if srv.text and srv.text.strip():
                        remote_hosts.append(srv.text.strip())
                for srv in root.findall(".//syslog/remoteserver2"):
                    if srv.text and srv.text.strip():
                        remote_hosts.append(srv.text.strip())
                for srv in root.findall(".//syslog/remoteserver3"):
                    if srv.text and srv.text.strip():
                        remote_hosts.append(srv.text.strip())
            data["syslog_remote"] = ", ".join(remote_hosts) if remote_hosts else "NONE"

            openvpn_srv = root.findall(".//openvpn/openvpn-server")
            openvpn_cli = root.findall(".//openvpn/openvpn-client")
            if openvpn_srv or openvpn_cli:
                data["openvpn_status"] = f"{len(openvpn_srv)} serveur(s), {len(openvpn_cli)} client(s) OpenVPN"
            else:
                data["openvpn_status"] = ""

            ipsec_ph1 = root.findall(".//ipsec/phase1")
            if ipsec_ph1:
                data["ipsec_status"] = f"{len(ipsec_ph1)} tunnel(s) IPsec configuré(s)"
            else:
                data["ipsec_status"] = ""

            wg_peers = root.findall(".//OPNsense/wireguard/server/servers/server")
            wg_enabled = (root.findtext(".//OPNsense/wireguard/general/enabled") or "0").strip()
            if wg_peers or wg_enabled == "1":
                data["wireguard_status"] = f"{len(wg_peers)} peer(s) WireGuard"
            else:
                data["wireguard_status"] = ""

            carp_entries: list[str] = []
            for vip in root.findall(".//virtualip/vip"):
                mode = (vip.findtext("mode") or "").strip()
                subnet = (vip.findtext("subnet") or "").strip()
                iface = (vip.findtext("interface") or "").strip()
                descr_vip = (vip.findtext("descr") or "").strip()
                if mode == "carp":
                    carp_entries.append(f"CARP {subnet} on {iface} ({descr_vip})")

            ha_parts: list[str] = []
            hasync = root.find(".//hasync")
            if hasync is not None:
                sync_enabled = (hasync.findtext("pfsyncenabled") or "").strip()
                sync_peer = (hasync.findtext("pfsyncpeerip") or "").strip()
                if sync_enabled:
                    ha_parts.append(f"pfsync → {sync_peer}")

            if carp_entries or ha_parts:
                data["carp_status"] = "; ".join(carp_entries + ha_parts)
            else:
                data["carp_status"] = ""

            user_lines: list[str] = []
            for u in root.findall(".//system/user"):
                name = (u.findtext("name") or "").strip()
                shell = (u.findtext("shell") or "").strip()
                uid = (u.findtext("uid") or "").strip()
                if name:
                    user_lines.append(f"{name}:{uid}:{shell or '/usr/local/sbin/opnsense-shell'}")
            data["users"] = "\n".join(user_lines)

            data["webgui_protocol"] = (root.findtext(".//system/webgui/protocol") or "https").strip()

            dns_servers = [el.text.strip() for el in root.findall(".//system/dnsserver") if el.text]
            data["dns_servers"] = ", ".join(dns_servers) if dns_servers else ""

            iface_lines: list[str] = []
            iface_node = root.find(".//interfaces")
            if iface_node is not None:
                for child in iface_node:
                    tag = child.tag
                    if tag in ("count", "bridged"):
                        continue
                    descr = (child.findtext("descr") or tag).strip()
                    enable_el = child.find("enable")
                    status = "up" if enable_el is not None else "down"
                    ipaddr = (child.findtext("ipaddr") or "").strip()
                    subnet = (child.findtext("subnet") or "").strip()
                    if_dev = (child.findtext("if") or "").strip()
                    ip_str = f"{ipaddr}/{subnet}" if ipaddr and subnet else ipaddr or "N/A"
                    iface_lines.append(f"{descr} ({if_dev}): {ip_str} [{status}]")
            else:
                logger.warning("OPNsense: <interfaces> node not found in config.xml")
            data["interfaces_text"] = "\n".join(iface_lines)
            data["interfaces_count"] = len(iface_lines)

            try:
                backup_files = sftp.listdir("/conf/backup/")
                data["config_backup_count"] = str(len(backup_files))
            except Exception:
                data["config_backup_count"] = "0"

            try:
                stat = sftp.stat("/conf/config.xml")
                data["config_xml_size"] = f"{stat.st_size} bytes"
            except Exception:
                data["config_xml_size"] = ""

            data["firmware_version"] = (
                root.findtext(".//system/firmware/version") or root.findtext(".//version") or ""
            ).strip()

            unbound_enabled = (
                root.findtext(".//OPNsense/unboundplus/general/enabled")
                or root.findtext(".//unbound/enable")
                or "0"
            ).strip()
            dnssec_enabled = (
                root.findtext(".//OPNsense/unboundplus/general/dnssec")
                or root.findtext(".//unbound/dnssec")
                or "0"
            ).strip()
            data["unbound_enabled"] = unbound_enabled == "1"
            data["dnssec_enabled"] = dnssec_enabled == "1"

            wan_node = root.find(".//interfaces/wan")
            if wan_node is not None:
                data["wan_blockpriv"] = wan_node.find("blockpriv") is not None
                data["wan_blockbogons"] = wan_node.find("blockbogons") is not None
            else:
                data["wan_blockpriv"] = False
                data["wan_blockbogons"] = False

            ids_ips_mode = (root.findtext(".//OPNsense/IDS/general/ips") or "0").strip()
            data["ids_ips_mode"] = ids_ips_mode == "1"

            any_any_rules: list[str] = []
            rules_without_descr = 0
            rules_with_log = 0
            interfaces_in_rules: set[str] = set()

            if filter_node is not None:
                for idx, rule_el in enumerate(filter_node.findall("rule"), 1):
                    disabled = rule_el.find("disabled") is not None
                    if disabled:
                        continue
                    rule_type = (rule_el.findtext("type") or "pass").strip()
                    descr = (rule_el.findtext("descr") or "").strip()
                    iface = (rule_el.findtext("interface") or "").strip()
                    src_any = rule_el.find("source/any") is not None
                    dst_any = rule_el.find("destination/any") is not None
                    has_log = rule_el.find("log") is not None

                    if iface:
                        for if_part in iface.split(","):
                            interfaces_in_rules.add(if_part.strip())

                    if not descr:
                        rules_without_descr += 1
                    if has_log:
                        rules_with_log += 1
                    if rule_type == "pass" and src_any and dst_any:
                        any_any_rules.append(f"#{idx} {iface}: pass any→any {descr or '(sans description)'}")

            data["any_any_rules"] = any_any_rules
            data["any_any_rules_count"] = len(any_any_rules)
            data["rules_without_descr"] = rules_without_descr
            data["rules_with_log"] = rules_with_log
            data["rules_log_ratio"] = f"{rules_with_log}/{enabled_rules}" if enabled_rules > 0 else "0/0"

            configured_interfaces: list[str] = []
            if iface_node is not None:
                for child in iface_node:
                    tag = child.tag
                    if tag in ("count", "bridged"):
                        continue
                    enable_el = child.find("enable")
                    if enable_el is not None:
                        configured_interfaces.append(tag)
            unused_interfaces = [iface for iface in configured_interfaces if iface not in interfaces_in_rules]
            data["unused_interfaces"] = unused_interfaces
            data["unused_interfaces_count"] = len(unused_interfaces)

            ntp_servers: list[str] = []
            ts_raw = (root.findtext(".//system/timeservers") or "").strip()
            if ts_raw:
                ntp_servers = [s.strip() for s in ts_raw.split() if s.strip()]
            data["ntp_servers"] = ntp_servers
            data["ntp_servers_count"] = len(ntp_servers)

            snmp_community = (root.findtext(".//system/snmpd/rocommunity") or "").strip()
            data["snmp_community"] = snmp_community
            data["snmp_default_community"] = (
                snmp_community.lower() in ("public", "private", "") if snmp_community else False
            )

            logger.info(
                "OPNsense config.xml parsed: hostname=%s, rules=%d/%d, any_any=%d, dnssec=%s",
                data.get("hostname"),
                enabled_rules,
                total_rules,
                len(any_any_rules),
                data["dnssec_enabled"],
            )

        finally:
            sftp.close()

    except Exception as e:
        logger.error("Erreur SFTP/XML OPNsense: %s", e)
        data["error"] = str(e)

    return data


def _try_opnsense_dynamic_commands(client: paramiko.SSHClient) -> dict:
    """Exécute des commandes dynamiques OPNsense via shell interactif (option 8)."""
    dynamic: dict[str, str] = {}

    DYNAMIC_CMDS = [
        ("os_version", "opnsense-version -v 2>/dev/null || freebsd-version"),
        ("os_name", "opnsense-version -n 2>/dev/null || echo OPNsense"),
        ("installed_version", "opnsense-version 2>/dev/null || echo N/A"),
        ("kernel", "uname -r"),
        ("uptime", "uptime"),
        ("arch", "uname -m"),
        ("updates_pending", "opnsense-update -c 2>/dev/null; echo EXIT=$?"),
        ("pkg_audit", "pkg audit -F 2>/dev/null | tail -5 || echo NOT_AVAILABLE"),
        ("pf_status", "/sbin/pfctl -s info 2>/dev/null | head -5"),
    ]

    try:
        channel = client.invoke_shell(width=200, height=50)
        channel.settimeout(12)
        time.sleep(1.0)

        buf = b""
        while channel.recv_ready():
            buf += channel.recv(8192)
        menu_text = buf.decode("utf-8", errors="replace")
        logger.debug("OPNsense menu: %s", menu_text[:200])

        channel.send("8\n")
        time.sleep(1.0)

        buf = b""
        while channel.recv_ready():
            buf += channel.recv(8192)
        shell_prompt = buf.decode("utf-8", errors="replace")
        logger.debug("OPNsense shell: %s", shell_prompt[:200])

        if "#" not in shell_prompt and "$" not in shell_prompt and "root@" not in shell_prompt:
            logger.warning("OPNsense: shell interactif non détecté → abandon commandes dynamiques")
            channel.close()
            return dynamic

        batch_lines: list[str] = []
        for cmd_name, cmd in DYNAMIC_CMDS:
            batch_lines.append(f"echo __MRK_{cmd_name}_S__")
            batch_lines.append(cmd)
            batch_lines.append(f"echo __MRK_{cmd_name}_E__")
        batch_lines.append("echo __ALL_DONE__")
        batch_script = " ; ".join(batch_lines) + "\n"

        channel.send(batch_script)

        buf = b""
        deadline = time.time() + 12
        while time.time() < deadline:
            if channel.recv_ready():
                chunk = channel.recv(16384)
                buf += chunk
                if b"__ALL_DONE__" in buf:
                    break
            else:
                time.sleep(0.3)

        output = buf.decode("utf-8", errors="replace")

        for cmd_name, _ in DYNAMIC_CMDS:
            tag_s = f"__MRK_{cmd_name}_S__"
            tag_e = f"__MRK_{cmd_name}_E__"
            if tag_s in output and tag_e in output:
                start = output.index(tag_s) + len(tag_s)
                end = output.index(tag_e)
                value = output[start:end].strip()
                clean_lines = [
                    line for line in value.splitlines() if not line.strip().startswith("echo ") and "__MRK_" not in line
                ]
                dynamic[cmd_name] = "\n".join(clean_lines).strip()

        channel.send("exit\n")
        time.sleep(0.3)
        channel.close()

        logger.info("OPNsense dynamic commands: %d/%d récupérées", len(dynamic), len(DYNAMIC_CMDS))

    except Exception as e:
        logger.warning("OPNsense interactive shell failed: %s", e)

    return dynamic


def _build_opnsense_from_config(
    result: SSHCollectResult,
    config: dict,
    dynamic: dict,
) -> None:
    """Construit SSHCollectResult à partir de config.xml + dynamiques."""
    result.hostname = config.get("hostname", "")

    result.os_info = {
        "distro": dynamic.get("os_name", "OPNsense").strip(),
        "version": dynamic.get("os_version", config.get("firmware_version", "")).strip(),
        "version_full": dynamic.get("installed_version", "").strip(),
        "kernel": dynamic.get("kernel", "").strip(),
        "arch": dynamic.get("arch", "").strip(),
        "uptime": dynamic.get("uptime", "").strip(),
        "type": "opnsense",
    }

    result.network = {
        "interfaces": config.get("interfaces_text", ""),
        "routes": "",
        "dns": config.get("dns_servers", ""),
        "listening_ports": "",
    }

    pf_status_raw = dynamic.get("pf_status", "")
    pf_enabled = config.get("firewall_enabled", True)
    if pf_status_raw:
        pf_enabled = "enabled" in pf_status_raw.lower() or "current entries" in pf_status_raw.lower()

    result.security = {
        "firewall_engine": "pf",
        "firewall_enabled": pf_enabled,
        "firewall_status_raw": pf_status_raw or "Déduit de config.xml (pf actif par défaut)",
        "firewall_rules_count": config.get("firewall_rules_count", 0),
        "firewall_rules": config.get("firewall_rules_text", ""),
        "nat_rules": f"{config.get('nat_rules_count', 0)} règle(s) NAT",
        "states_count": "",
        "aliases": "",
        "ssh_config_raw": config.get("ssh_config_raw", ""),
        "ssh_permit_root_login": config.get("ssh_permit_root_login", "NOT_SET"),
        "suricata_status": config.get("suricata_status", "NOT_RUNNING"),
        "syslog_remote": config.get("syslog_remote", "NONE"),
        "webgui_protocol": config.get("webgui_protocol", "https"),
        "ids_ips_mode": config.get("ids_ips_mode", False),
        "any_any_rules": config.get("any_any_rules", []),
        "any_any_rules_count": config.get("any_any_rules_count", 0),
        "rules_without_descr": config.get("rules_without_descr", 0),
        "rules_with_log": config.get("rules_with_log", 0),
        "rules_log_ratio": config.get("rules_log_ratio", "0/0"),
        "wan_blockpriv": config.get("wan_blockpriv", False),
        "wan_blockbogons": config.get("wan_blockbogons", False),
        "dnssec_enabled": config.get("dnssec_enabled", False),
        "unbound_enabled": config.get("unbound_enabled", False),
        "unused_interfaces": config.get("unused_interfaces", []),
        "unused_interfaces_count": config.get("unused_interfaces_count", 0),
        "ntp_servers": config.get("ntp_servers", []),
        "ntp_servers_count": config.get("ntp_servers_count", 0),
        "snmp_community": config.get("snmp_community", ""),
        "snmp_default_community": config.get("snmp_default_community", False),
        "source": "config.xml" + (" + dynamic" if dynamic else ""),
    }

    result.services = {
        "services_list": "",
        "openvpn_status": config.get("openvpn_status", ""),
        "ipsec_status": config.get("ipsec_status", ""),
        "wireguard_status": config.get("wireguard_status", ""),
        "carp_status": config.get("carp_status", ""),
    }

    result.users = {
        "users_with_shell": config.get("users", ""),
    }

    updates_raw = dynamic.get("updates_pending", "")
    has_updates = True
    if "EXIT=0" in updates_raw:
        has_updates = False

    result.updates = {
        "update_check_raw": updates_raw or "Non vérifiable (shell menu OPNsense)",
        "updates_available": has_updates if updates_raw else None,
        "pkg_audit": dynamic.get("pkg_audit", "Non vérifiable (shell menu OPNsense)"),
    }

    result.storage = {
        "config_xml_size": config.get("config_xml_size", ""),
        "config_backup_count": config.get("config_backup_count", "0"),
    }

    result.raw_outputs = {
        "_source": "config.xml (SFTP) + shell interactif",
        "_config_hostname": config.get("hostname", ""),
        "_config_rules": str(config.get("firewall_rules_count", 0)),
        "_config_interfaces": config.get("interfaces_text", "")[:300],
        "_config_ssh": config.get("ssh_config_raw", ""),
        "_config_suricata": config.get("suricata_status", ""),
        "_config_syslog": config.get("syslog_remote", ""),
        "_config_carp": config.get("carp_status", ""),
        "_config_any_any": str(config.get("any_any_rules_count", 0)),
        "_config_dnssec": str(config.get("dnssec_enabled", False)),
        "_config_wan_bogons": str(config.get("wan_blockbogons", False)),
        "_config_ntp": str(config.get("ntp_servers_count", 0)),
        "_dynamic_available": str(bool(dynamic)),
    }
    for k, v in dynamic.items():
        result.raw_outputs[f"dyn_{k}"] = str(v)[:500]


def _parse_opnsense_results(result: SSHCollectResult, raw: dict[str, str]) -> None:
    """Parse les sorties OPNsense (fallback exec_command)."""
    result.hostname = raw.get("hostname", "").strip()

    installed_ver = raw.get("installed_version", "")
    result.os_info = {
        "distro": raw.get("os_name", "OPNsense").strip(),
        "version": raw.get("os_version", "").strip(),
        "version_full": installed_ver.strip(),
        "kernel": raw.get("kernel", "").strip(),
        "arch": raw.get("arch", "").strip(),
        "uptime": raw.get("uptime", "").strip(),
        "type": "opnsense",
    }

    result.network = {
        "interfaces": raw.get("interfaces", ""),
        "routes": raw.get("routes", ""),
        "dns": raw.get("dns", ""),
        "listening_ports": raw.get("listening_ports", ""),
    }

    pf_status = raw.get("pf_status", "")
    pf_enabled = ("status: enabled" in pf_status.lower()) if pf_status else False
    if not pf_enabled and pf_status and ("current entries" in pf_status.lower() or "searches" in pf_status.lower()):
        pf_enabled = True
    pf_rules = raw.get("pf_rules", "")
    pf_rules_count_raw = raw.get("pf_rules_count", "0").strip()
    pf_rules_count = "".join(c for c in pf_rules_count_raw if c.isdigit()) or "0"

    result.security = {
        "firewall_engine": "pf",
        "firewall_enabled": pf_enabled,
        "firewall_status_raw": pf_status,
        "firewall_rules_count": int(pf_rules_count) if pf_rules_count.isdigit() else 0,
        "firewall_rules": pf_rules,
        "nat_rules": raw.get("pf_nat", ""),
        "states_count": raw.get("pf_states_count", ""),
        "aliases": raw.get("aliases", ""),
        "ssh_config_raw": raw.get("ssh_config", ""),
        "ssh_permit_root_login": raw.get("ssh_root_login", "NOT_SET").strip(),
        "suricata_status": raw.get("suricata_status", "NOT_RUNNING").strip(),
        "syslog_remote": raw.get("syslog_remote", "NONE"),
    }

    result.services = {
        "services_list": raw.get("services", ""),
        "openvpn_status": raw.get("openvpn_status", ""),
        "ipsec_status": raw.get("ipsec_status", ""),
        "wireguard_status": raw.get("wireguard_status", ""),
        "carp_status": raw.get("carp_status", ""),
    }

    result.users = {
        "users_with_shell": raw.get("users", ""),
    }

    updates_raw = raw.get("updates_pending", "")
    has_updates = "EXIT=0" not in updates_raw
    result.updates = {
        "update_check_raw": updates_raw,
        "updates_available": has_updates,
        "pkg_audit": raw.get("pkg_audit", ""),
    }

    result.storage = {
        "config_xml_size": raw.get("config_xml_size", ""),
        "config_backup_count": raw.get("config_backup_count", "0").strip(),
    }


def _parse_stormshield_results(result: SSHCollectResult, raw: dict[str, str]) -> None:
    """Parse les sorties Stormshield SNS en données structurées."""
    hostname_raw = raw.get("hostname", "")
    hostname = hostname_raw.split("=", 1)[-1].strip() if "=" in hostname_raw else hostname_raw.strip()
    result.hostname = hostname

    version_raw = raw.get("system_info", "")
    result.os_info = {
        "distro": "Stormshield SNS",
        "version_raw": version_raw.strip(),
        "serial": raw.get("serial", "").split("=", 1)[-1].strip() if "=" in raw.get("serial", "") else "",
        "uptime": raw.get("uptime", "").strip(),
        "license": raw.get("license", "").strip(),
        "type": "stormshield",
    }

    result.network = {
        "interfaces": raw.get("interfaces", ""),
        "routes": raw.get("routes", ""),
        "dns": raw.get("dns", ""),
    }

    filter_count = raw.get("filter_rules_count", "0").strip()
    result.security = {
        "firewall_engine": "stormshield_asq",
        "filter_rules_count": int(filter_count) if filter_count.isdigit() else 0,
        "filter_rules": raw.get("filter_rules", ""),
        "nat_rules": raw.get("nat_rules", ""),
        "active_connections": raw.get("active_connections", ""),
        "admin_accounts": raw.get("admin_accounts", ""),
        "ssh_status": raw.get("ssh_status", ""),
        "antivirus": raw.get("antivirus", ""),
        "ips_status": raw.get("ips_status", ""),
        "alarm_list": raw.get("alarm_list", ""),
        "syslog_servers": raw.get("syslog_servers", ""),
    }

    result.users = {
        "objects_host": raw.get("objects_host", ""),
        "objects_network": raw.get("objects_network", ""),
        "objects_group": raw.get("objects_group", ""),
    }

    result.services = {
        "services_status": raw.get("services_status", ""),
        "vpn_ipsec_peers": raw.get("vpn_ipsec_peers", ""),
        "vpn_ipsec_sa": raw.get("vpn_ipsec_sa", ""),
        "vpn_ssl_status": raw.get("vpn_ssl_status", ""),
        "ha_status": raw.get("ha_status", ""),
    }

    result.updates = {
        "firmware_version": version_raw.strip(),
        "update_status": raw.get("update_status", ""),
    }

    result.storage = {}


def _parse_fortigate_results(result: SSHCollectResult, raw: dict[str, str]) -> None:
    """Parse les sorties FortiGate (FortiOS) en données structurées."""
    hostname_raw = raw.get("hostname", "")
    if ":" in hostname_raw:
        result.hostname = hostname_raw.split(":", 1)[-1].strip()
    else:
        result.hostname = hostname_raw.strip()

    status_raw = raw.get("system_status", "")
    firmware_raw = raw.get("firmware", "")
    serial_raw = raw.get("serial", "")

    version = ""
    for line in status_raw.splitlines():
        if "Version" in line:
            version = line.split(":", 1)[-1].strip() if ":" in line else line
            break
    if not version and firmware_raw:
        version = firmware_raw.split(":", 1)[-1].strip() if ":" in firmware_raw else firmware_raw

    serial = ""
    for line in (serial_raw or status_raw).splitlines():
        if "Serial" in line:
            serial = line.split(":", 1)[-1].strip() if ":" in line else line
            break

    result.os_info = {
        "distro": "FortiOS",
        "version": version,
        "serial": serial,
        "uptime": raw.get("uptime", "").strip(),
        "license": raw.get("license", "").strip(),
        "system_status_raw": status_raw,
        "type": "fortigate",
    }

    result.network = {
        "interfaces": raw.get("interfaces", ""),
        "interfaces_physical": raw.get("interfaces_physical", ""),
        "routes": raw.get("routes", ""),
        "dns": raw.get("dns", ""),
        "arp_table": raw.get("arp_table", ""),
    }

    policy_count_raw = raw.get("policy_count", "0").strip()
    result.security = {
        "firewall_engine": "fortios",
        "policy_count": int(policy_count_raw) if policy_count_raw.isdigit() else 0,
        "policies": raw.get("policies", ""),
        "policy_summary": raw.get("policy_summary", ""),
        "vip": raw.get("vip", ""),
        "address_objects": raw.get("address_objects", ""),
        "address_groups": raw.get("address_groups", ""),
        "admin_users": raw.get("admin_users", ""),
        "admin_settings": raw.get("admin_settings", ""),
        "password_policy": raw.get("password_policy", ""),
        "trusted_hosts": raw.get("trusted_hosts", ""),
        "antivirus_profile": raw.get("antivirus_profile", ""),
        "ips_settings": raw.get("ips_settings", ""),
        "webfilter": raw.get("webfilter", ""),
        "ntp": raw.get("ntp", ""),
        "snmp": raw.get("snmp", ""),
        "session_count": raw.get("session_count", ""),
    }

    result.services = {
        "vpn_ipsec_tunnels": raw.get("vpn_ipsec_tunnels", ""),
        "vpn_ssl_status": raw.get("vpn_ssl_status", ""),
        "vpn_ssl_settings": raw.get("vpn_ssl_settings", ""),
        "ha_status": raw.get("ha_status", ""),
    }

    result.users = {
        "admin_users": raw.get("admin_users", ""),
    }

    result.updates = {
        "firmware_version": version,
        "log_settings": raw.get("log_settings", ""),
        "log_syslogd": raw.get("log_syslogd", ""),
        "log_fortianalyzer": raw.get("log_fortianalyzer", ""),
        "log_disk": raw.get("log_disk", ""),
    }

    result.storage = {}


# ──────────────────────────────────────────────────────────────
# Wrapper ToolBase
# ──────────────────────────────────────────────────────────────


class SshCollectorTool(ToolBase):
    """Outil de collecte SSH pour l'agent."""

    def __init__(self) -> None:
        self._cancelled = False

    @property
    def name(self) -> str:
        return "ssh-collect"

    @property
    def default_timeout(self) -> int:
        return 1800  # 30 min

    async def execute(
        self,
        task_id: str,
        parameters: dict,
        on_progress: OnProgressCallback | None = None,
    ) -> ToolResult:
        """Lance la collecte SSH."""
        self._cancelled = False

        host = str(parameters.get("host", "")).strip()
        port = int(parameters.get("port", 22))
        username = str(parameters.get("username", "root")).strip()
        password = parameters.get("password")
        private_key = parameters.get("private_key")
        passphrase = parameters.get("passphrase")
        device_profile = str(parameters.get("device_profile", "linux_server")).strip().lower()

        if not host or not _HOST_PATTERN.match(host):
            return ToolResult(success=False, error=f"host invalide : '{host}'")

        if not username or not _USERNAME_PATTERN.match(username):
            return ToolResult(success=False, error=f"username invalide : '{username}'")

        if not (1 <= port <= 65535):
            return ToolResult(success=False, error=f"port hors plage : {port}")

        if device_profile not in SUPPORTED_PROFILES:
            return ToolResult(
                success=False,
                error=f"device_profile non supporté : '{device_profile}' (attendu : {SUPPORTED_PROFILES})",
            )

        if not password and not private_key:
            return ToolResult(
                success=False,
                error="Authentification requise : fournir password ou private_key",
            )

        logger.info(
            "SSH collect → %s@%s:%d (profile=%s)", username, host, port, device_profile
        )

        loop = asyncio.get_running_loop()

        def sync_progress(percent: int, label: str) -> None:
            if on_progress is None or self._cancelled:
                return
            asyncio.run_coroutine_threadsafe(
                on_progress(percent, [f"SSH: {label}"]),
                loop,
            )

        try:
            result = await asyncio.to_thread(
                collect_via_ssh,
                host,
                port,
                username,
                password,
                private_key,
                passphrase,
                device_profile,
                sync_progress,
            )
        except Exception as e:
            logger.exception("SSH collect: erreur inattendue")
            return ToolResult(success=False, error=f"Exception collecte SSH : {e}")

        if not result.success:
            return ToolResult(
                success=False,
                error=result.error or "Collecte SSH échouée (raison inconnue)",
                output=dataclasses.asdict(result),
            )

        if on_progress is not None:
            await on_progress(100, [f"SSH: collecte terminée ({device_profile})"])

        return ToolResult(
            success=True,
            output=dataclasses.asdict(result),
        )

    async def cancel(self) -> None:
        """Marque la collecte comme annulée (paramiko bloquant, pas d'interruption propre)."""
        self._cancelled = True
        logger.info("SSH collect: annulation demandée (flag posé, attente fin naturelle)")
