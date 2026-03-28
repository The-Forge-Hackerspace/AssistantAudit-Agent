"""Configuration de l'agent — chargement/sauvegarde de agent.json avec chiffrement DPAPI."""

from __future__ import annotations

import base64
import json
import logging
from pathlib import Path

from pydantic import BaseModel

logger = logging.getLogger("config")

DEFAULT_CONFIG_PATH = Path("agent.json")


class CertPaths(BaseModel):
    """Chemins vers les certificats mTLS."""

    ca: str = "certs/ca.pem"
    cert: str = "certs/agent.pem"
    key: str = "certs/agent.key"


class AgentConfig(BaseModel):
    """Configuration complète de l'agent."""

    agent_uuid: str
    server_url: str
    jwt_token: str
    agent_name: str
    allowed_tools: list[str] = ["nmap", "oradad", "ad_collector"]
    heartbeat_interval: int = 30
    cert_paths: CertPaths = CertPaths()
    reconnect_base_delay: float = 1.0
    reconnect_max_delay: float = 60.0

    @classmethod
    def load(cls, path: Path = DEFAULT_CONFIG_PATH) -> AgentConfig:
        """Charge la configuration depuis agent.json et déchiffre le JWT.

        Raises:
            FileNotFoundError: Si le fichier n'existe pas.
            json.JSONDecodeError: Si le JSON est invalide.
        """
        raw = json.loads(path.read_text(encoding="utf-8"))
        raw["jwt_token"] = _decrypt_token(raw["jwt_token"])
        return cls.model_validate(raw)

    def save(self, path: Path = DEFAULT_CONFIG_PATH) -> None:
        """Chiffre le JWT et écrit la configuration dans agent.json."""
        data = self.model_dump()
        data["jwt_token"] = _encrypt_token(self.jwt_token)
        path.write_text(json.dumps(data, indent=2, ensure_ascii=False), encoding="utf-8")
        logger.info("Configuration sauvegardée dans %s", path)

    @staticmethod
    def is_enrolled(path: Path = DEFAULT_CONFIG_PATH) -> bool:
        """Vérifie que agent.json existe et contient un UUID valide."""
        if not path.exists():
            return False
        try:
            raw = json.loads(path.read_text(encoding="utf-8"))
            return bool(raw.get("agent_uuid"))
        except (json.JSONDecodeError, OSError):
            return False


# ---------------------------------------------------------------------------
# Chiffrement DPAPI (Windows) avec fallback base64
# ---------------------------------------------------------------------------

_DPAPI_PREFIX = "dpapi:"
_B64_PREFIX = "b64:"


def _dpapi_available() -> bool:
    """Vérifie si DPAPI (win32crypt) est disponible."""
    try:
        import win32crypt  # noqa: F401
        return True
    except ImportError:
        return False


def _encrypt_token(token: str) -> str:
    """Chiffre le JWT avec DPAPI si disponible, sinon base64 (avec warning)."""
    token_bytes = token.encode("utf-8")

    if _dpapi_available():
        import win32crypt
        encrypted = win32crypt.CryptProtectData(
            token_bytes,
            "AssistantAudit-Agent JWT",
            None,
            None,
            None,
            0,
        )
        return _DPAPI_PREFIX + base64.b64encode(encrypted).decode("ascii")

    logger.warning(
        "DPAPI non disponible — le JWT sera stocké en base64 (non sécurisé). "
        "Installez pywin32 pour le chiffrement DPAPI."
    )
    return _B64_PREFIX + base64.b64encode(token_bytes).decode("ascii")


def _decrypt_token(encrypted: str) -> str:
    """Déchiffre le JWT depuis le format stocké sur disque."""
    if encrypted.startswith(_DPAPI_PREFIX):
        if not _dpapi_available():
            raise RuntimeError(
                "Le JWT est chiffré avec DPAPI mais win32crypt n'est pas disponible. "
                "Installez pywin32 ou ré-enrollez l'agent."
            )
        import win32crypt
        raw = base64.b64decode(encrypted[len(_DPAPI_PREFIX) :])
        _, decrypted = win32crypt.CryptUnprotectData(raw, None, None, None, 0)
        return decrypted.decode("utf-8")

    if encrypted.startswith(_B64_PREFIX):
        return base64.b64decode(encrypted[len(_B64_PREFIX) :]).decode("utf-8")

    # Token en clair (migration depuis une ancienne version)
    logger.warning("JWT stocké en clair — il sera chiffré à la prochaine sauvegarde.")
    return encrypted
