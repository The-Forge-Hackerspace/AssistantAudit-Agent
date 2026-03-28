"""Flux d'enrollment initial de l'agent auprès du serveur.

Échange un code d'enrollment (usage unique, 10 min) contre :
- Un JWT agent (30 jours)
- Un certificat client mTLS signé par la CA interne
- Une clé privée associée

Le serveur retourne : {agent_uuid, agent_token, client_cert_pem, client_key_pem}.
Le CA cert (ca.pem) n'est PAS inclus dans la réponse — il doit être fourni
séparément via --ca-cert ou pré-distribué sur le poste.
"""

from __future__ import annotations

import logging
import os
import platform
import stat
import sys
from dataclasses import dataclass
from pathlib import Path

import httpx

from assistant_audit_agent.config import AgentConfig, CertPaths, DEFAULT_CONFIG_PATH

logger = logging.getLogger("enrollment")

ENROLL_ENDPOINT = "/api/v1/agents/enroll"
ENROLL_TIMEOUT = 10.0


@dataclass(frozen=True)
class EnrollResult:
    """Résultat d'un enrollment réussi."""

    agent_uuid: str
    agent_name: str
    server_url: str


class EnrollmentError(Exception):
    """Erreur pendant l'enrollment."""


def enroll(
    server_url: str,
    enrollment_code: str,
    agent_name: str | None = None,
    ca_cert_path: str | None = None,
    config_path: Path = DEFAULT_CONFIG_PATH,
) -> EnrollResult:
    """Enrôle l'agent auprès du serveur AssistantAudit.

    Args:
        server_url: URL de base du serveur (ex: https://server:8000).
        enrollment_code: Code d'enrollment fourni par l'admin.
        agent_name: Nom de l'agent. Si None, utilise le hostname.
        ca_cert_path: Chemin vers le CA cert pour vérifier le serveur.
                      Si None, la vérification TLS est désactivée (premier appel).
        config_path: Chemin vers agent.json.

    Returns:
        EnrollResult avec les infos de l'agent enrollé.

    Raises:
        EnrollmentError: En cas d'échec (code invalide, serveur injoignable, etc.)
    """
    effective_name = agent_name or platform.node()
    url = server_url.rstrip("/") + ENROLL_ENDPOINT

    # Premier appel : pas encore de CA cert → verify=False est acceptable.
    # Après enrollment, toutes les connexions utiliseront le ca.pem reçu.
    verify = ca_cert_path if ca_cert_path else False

    logger.info("Enrollment auprès de %s...", server_url)

    try:
        response = httpx.post(
            url,
            json={"enrollment_code": enrollment_code},
            verify=verify,
            timeout=ENROLL_TIMEOUT,
        )
    except httpx.ConnectError:
        raise EnrollmentError(f"Serveur injoignable à {server_url}")
    except httpx.TimeoutException:
        raise EnrollmentError(f"Serveur injoignable à {server_url} (timeout {ENROLL_TIMEOUT}s)")

    if response.status_code == 400:
        detail = _extract_detail(response)
        raise EnrollmentError(f"Code invalide ou expiré : {detail}")

    if response.status_code == 429:
        raise EnrollmentError("Trop de tentatives d'enrollment — réessayez plus tard.")

    if response.status_code != 200:
        detail = _extract_detail(response)
        raise EnrollmentError(f"Erreur serveur ({response.status_code}) : {detail}")

    data = response.json()

    # Valider les champs attendus (EnrollResponse du serveur)
    agent_uuid = data.get("agent_uuid", "")
    agent_token = data.get("agent_token", "")
    client_cert_pem = data.get("client_cert_pem", "")
    client_key_pem = data.get("client_key_pem", "")

    if not agent_uuid or not agent_token:
        raise EnrollmentError("Réponse serveur incomplète (UUID ou token manquant).")

    # Écrire les certificats mTLS
    certs_dir = Path("certs")
    cert_paths = CertPaths()
    try:
        _write_certs(certs_dir, cert_paths, client_cert_pem, client_key_pem, ca_cert_path)
    except OSError as exc:
        _cleanup_partial_files(certs_dir, cert_paths)
        raise EnrollmentError(f"Erreur d'écriture des certificats : {exc}")

    # Sauvegarder la configuration
    config = AgentConfig(
        agent_uuid=agent_uuid,
        server_url=server_url.rstrip("/"),
        jwt_token=agent_token,
        agent_name=effective_name,
        cert_paths=cert_paths,
    )

    try:
        config.save(config_path)
    except OSError as exc:
        _cleanup_partial_files(certs_dir, cert_paths)
        raise EnrollmentError(f"Erreur d'écriture de la configuration : {exc}")

    logger.info("Enrollment réussi : agent '%s' (%s)", effective_name, agent_uuid)
    return EnrollResult(
        agent_uuid=agent_uuid,
        agent_name=effective_name,
        server_url=server_url,
    )


def _write_certs(
    certs_dir: Path,
    cert_paths: CertPaths,
    client_cert_pem: str,
    client_key_pem: str,
    ca_cert_source: str | None,
) -> None:
    """Écrit les certificats mTLS sur disque avec permissions restrictives."""
    certs_dir.mkdir(parents=True, exist_ok=True)

    # Certificat client
    if client_cert_pem:
        Path(cert_paths.cert).write_text(client_cert_pem, encoding="utf-8")

    # Clé privée — permissions restrictives
    if client_key_pem:
        key_path = Path(cert_paths.key)
        # Rétablir les permissions en écriture si le fichier existe déjà (ré-enrollment)
        if key_path.exists():
            _make_writable(key_path)
        key_path.write_text(client_key_pem, encoding="utf-8")
        _restrict_file_permissions(key_path)

    # CA cert — copier depuis le fichier source s'il existe
    if ca_cert_source and Path(ca_cert_source).exists():
        ca_content = Path(ca_cert_source).read_text(encoding="utf-8")
        Path(cert_paths.ca).write_text(ca_content, encoding="utf-8")


def _restrict_file_permissions(path: Path) -> None:
    """Restreint les permissions du fichier à lecture seule pour le propriétaire.

    Sur Windows, utilise icacls pour retirer l'héritage et ne garder que l'utilisateur courant.
    Sur Unix, utilise chmod 0o400.
    """
    if sys.platform == "win32":
        import subprocess

        abs_path = str(path.resolve())
        username = os.environ.get("USERNAME", os.environ.get("USER", ""))
        if username:
            subprocess.run(
                ["icacls", abs_path, "/inheritance:r",
                 "/grant:r", f"{username}:(R)"],
                capture_output=True,
                check=False,
            )
    else:
        path.chmod(stat.S_IRUSR)


def _make_writable(path: Path) -> None:
    """Rétablit les permissions en écriture sur un fichier (pour ré-enrollment)."""
    if sys.platform == "win32":
        import subprocess

        abs_path = str(path.resolve())
        username = os.environ.get("USERNAME", os.environ.get("USER", ""))
        if username:
            subprocess.run(
                ["icacls", abs_path, "/grant:r", f"{username}:(W)"],
                capture_output=True,
                check=False,
            )
    else:
        path.chmod(stat.S_IWUSR | stat.S_IRUSR)


def _cleanup_partial_files(certs_dir: Path, cert_paths: CertPaths) -> None:
    """Supprime les fichiers partiellement créés en cas d'erreur."""
    for p in [cert_paths.cert, cert_paths.key, cert_paths.ca]:
        try:
            fp = Path(p)
            if fp.exists():
                _make_writable(fp)
                fp.unlink()
        except OSError:
            pass
    logger.warning("Fichiers partiels nettoyés après erreur d'enrollment.")


def _extract_detail(response: httpx.Response) -> str:
    """Extrait le message d'erreur du corps de la réponse."""
    try:
        return response.json().get("detail", response.text)
    except Exception:
        return response.text
