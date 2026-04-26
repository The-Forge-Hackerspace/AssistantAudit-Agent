"""Tests pour la configuration de l'agent (load, save, chiffrement JWT)."""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from assistant_audit_agent.config import (
    AgentConfig,
    CertPaths,
    _decrypt_token,
    _encrypt_token,
)


@pytest.fixture()
def sample_config() -> AgentConfig:
    return AgentConfig(
        agent_uuid="550e8400-e29b-41d4-a716-446655440000",
        server_url="https://server:8000",
        jwt_token="eyJhbGciOiJIUzI1NiJ9.test.signature",
        agent_name="PC-Test-01",
        allowed_tools=["nmap", "oradad"],
    )


@pytest.fixture()
def config_path(tmp_path: Path) -> Path:
    return tmp_path / "agent.json"


class TestAgentConfigSaveLoad:
    """Tests de sauvegarde et chargement de la config."""

    def test_save_creates_file(self, sample_config: AgentConfig, config_path: Path) -> None:
        sample_config.save(config_path)
        assert config_path.exists()

    def test_load_roundtrip(self, sample_config: AgentConfig, config_path: Path) -> None:
        sample_config.save(config_path)
        loaded = AgentConfig.load(config_path)
        assert loaded.agent_uuid == sample_config.agent_uuid
        assert loaded.server_url == sample_config.server_url
        assert loaded.jwt_token == sample_config.jwt_token
        assert loaded.agent_name == sample_config.agent_name
        assert loaded.allowed_tools == sample_config.allowed_tools

    def test_jwt_encrypted_on_disk(self, sample_config: AgentConfig, config_path: Path) -> None:
        """Le JWT ne doit pas apparaître en clair dans le fichier."""
        sample_config.save(config_path)
        raw = json.loads(config_path.read_text(encoding="utf-8"))
        assert raw["jwt_token"] != sample_config.jwt_token
        assert raw["jwt_token"].startswith(("dpapi:", "b64:"))

    def test_load_nonexistent_raises(self, tmp_path: Path) -> None:
        with pytest.raises(FileNotFoundError):
            AgentConfig.load(tmp_path / "missing.json")

    def test_default_values(self, sample_config: AgentConfig) -> None:
        assert sample_config.heartbeat_interval == 30
        assert sample_config.reconnect_base_delay == 1.0
        assert sample_config.reconnect_max_delay == 60.0
        assert sample_config.cert_paths == CertPaths()


class TestIsEnrolled:
    """Tests de vérification d'enrollment."""

    def test_not_enrolled_when_file_missing(self, tmp_path: Path) -> None:
        assert AgentConfig.is_enrolled(tmp_path / "nope.json") is False

    def test_enrolled_when_uuid_present(self, sample_config: AgentConfig, config_path: Path) -> None:
        sample_config.save(config_path)
        assert AgentConfig.is_enrolled(config_path) is True

    def test_not_enrolled_when_uuid_empty(self, config_path: Path) -> None:
        config_path.write_text(json.dumps({"agent_uuid": ""}), encoding="utf-8")
        assert AgentConfig.is_enrolled(config_path) is False

    def test_not_enrolled_on_invalid_json(self, config_path: Path) -> None:
        config_path.write_text("{bad json", encoding="utf-8")
        assert AgentConfig.is_enrolled(config_path) is False


class TestTokenEncryption:
    """Tests du chiffrement/déchiffrement du JWT (fallback base64)."""

    def test_b64_roundtrip(self) -> None:
        original = "my-secret-jwt-token"
        encrypted = _encrypt_token(original)
        assert encrypted.startswith(("dpapi:", "b64:"))
        decrypted = _decrypt_token(encrypted)
        assert decrypted == original

    def test_plaintext_fallback(self) -> None:
        """Un token en clair (ancienne version) doit être déchiffré tel quel."""
        assert _decrypt_token("plaintext-token") == "plaintext-token"
