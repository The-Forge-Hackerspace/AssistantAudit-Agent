"""Tests pour le flux d'enrollment de l'agent."""

from __future__ import annotations

import json
import logging
import stat
import sys
from pathlib import Path

import httpx
import pytest
from click.testing import CliRunner

from assistant_audit_agent.config import AgentConfig
from assistant_audit_agent.enrollment import (
    ENROLL_TIMEOUT,
    EnrollmentError,
    enroll,
)
from assistant_audit_agent.main import cli


# ── Fixtures ─────────────────────────────────────────────────────────


FAKE_ENROLL_RESPONSE = {
    "agent_uuid": "550e8400-e29b-41d4-a716-446655440000",
    "agent_token": "eyJhbGciOiJIUzI1NiJ9.fake-agent-token.sig",
    "client_cert_pem": "-----BEGIN CERTIFICATE-----\nMIIBfake...\n-----END CERTIFICATE-----\n",
    "client_key_pem": "-----BEGIN PRIVATE KEY-----\nMIIBfake...\n-----END PRIVATE KEY-----\n",
}


def _mock_response(status_code: int = 200, json_data: dict | None = None) -> httpx.Response:
    """Crée une fausse réponse httpx."""
    data = json_data or FAKE_ENROLL_RESPONSE
    return httpx.Response(
        status_code=status_code,
        json=data,
        request=httpx.Request("POST", "https://server:8000/api/v1/agents/enroll"),
    )


@pytest.fixture()
def work_dir(tmp_path: Path, monkeypatch) -> Path:
    """Répertoire de travail temporaire pour chaque test."""
    monkeypatch.chdir(tmp_path)
    (tmp_path / "certs").mkdir()
    return tmp_path


# ── Tests enrollment réussi ──────────────────────────────────────────


class TestEnrollSuccess:
    """Enrollment réussi — vérification des fichiers créés."""

    def test_creates_agent_json(self, work_dir: Path, monkeypatch) -> None:
        monkeypatch.setattr(httpx, "post", lambda *a, **kw: _mock_response())
        result = enroll("https://server:8000", "ABCD1234", agent_name="PC-Test")

        assert result.agent_uuid == FAKE_ENROLL_RESPONSE["agent_uuid"]
        assert result.agent_name == "PC-Test"
        assert AgentConfig.is_enrolled()

    def test_config_roundtrip(self, work_dir: Path, monkeypatch) -> None:
        monkeypatch.setattr(httpx, "post", lambda *a, **kw: _mock_response())
        enroll("https://server:8000", "ABCD1234", agent_name="PC-Test")

        config = AgentConfig.load()
        assert config.agent_uuid == FAKE_ENROLL_RESPONSE["agent_uuid"]
        assert config.jwt_token == FAKE_ENROLL_RESPONSE["agent_token"]
        assert config.server_url == "https://server:8000"
        assert config.agent_name == "PC-Test"

    def test_writes_client_cert(self, work_dir: Path, monkeypatch) -> None:
        monkeypatch.setattr(httpx, "post", lambda *a, **kw: _mock_response())
        enroll("https://server:8000", "ABCD1234")

        cert_path = work_dir / "certs" / "agent.pem"
        assert cert_path.exists()
        assert cert_path.read_text(encoding="utf-8") == FAKE_ENROLL_RESPONSE["client_cert_pem"]

    def test_writes_client_key(self, work_dir: Path, monkeypatch) -> None:
        monkeypatch.setattr(httpx, "post", lambda *a, **kw: _mock_response())
        enroll("https://server:8000", "ABCD1234")

        key_path = work_dir / "certs" / "agent.key"
        assert key_path.exists()
        assert key_path.read_text(encoding="utf-8") == FAKE_ENROLL_RESPONSE["client_key_pem"]

    def test_key_has_restricted_permissions(self, work_dir: Path, monkeypatch) -> None:
        monkeypatch.setattr(httpx, "post", lambda *a, **kw: _mock_response())
        enroll("https://server:8000", "ABCD1234")

        key_path = work_dir / "certs" / "agent.key"
        assert key_path.exists()
        if sys.platform != "win32":
            mode = key_path.stat().st_mode
            assert mode & stat.S_IRUSR  # owner can read
            assert not (mode & stat.S_IWOTH)  # others can't write

    def test_uses_hostname_when_no_name(self, work_dir: Path, monkeypatch) -> None:
        monkeypatch.setattr(httpx, "post", lambda *a, **kw: _mock_response())
        monkeypatch.setattr("platform.node", lambda: "LAPTOP-TECH01")
        result = enroll("https://server:8000", "ABCD1234")
        assert result.agent_name == "LAPTOP-TECH01"

    def test_copies_ca_cert(self, work_dir: Path, monkeypatch) -> None:
        monkeypatch.setattr(httpx, "post", lambda *a, **kw: _mock_response())
        ca_source = work_dir / "my-ca.pem"
        ca_source.write_text("-----BEGIN CERTIFICATE-----\nCA...\n-----END CERTIFICATE-----\n")

        enroll("https://server:8000", "ABCD1234", ca_cert_path=str(ca_source))

        ca_dest = work_dir / "certs" / "ca.pem"
        assert ca_dest.exists()
        assert ca_dest.read_text(encoding="utf-8") == ca_source.read_text(encoding="utf-8")

    def test_jwt_encrypted_on_disk(self, work_dir: Path, monkeypatch) -> None:
        monkeypatch.setattr(httpx, "post", lambda *a, **kw: _mock_response())
        enroll("https://server:8000", "ABCD1234")

        raw = json.loads((work_dir / "agent.json").read_text(encoding="utf-8"))
        assert raw["jwt_token"] != FAKE_ENROLL_RESPONSE["agent_token"]
        assert raw["jwt_token"].startswith(("dpapi:", "b64:"))


# ── Tests erreurs ────────────────────────────────────────────────────


class TestEnrollErrors:
    """Gestion des erreurs d'enrollment."""

    def test_invalid_code_400(self, work_dir: Path, monkeypatch) -> None:
        resp = _mock_response(400, {"detail": "Code d'enrollment invalide ou expire"})
        monkeypatch.setattr(httpx, "post", lambda *a, **kw: resp)

        with pytest.raises(EnrollmentError, match="Code invalide ou expiré"):
            enroll("https://server:8000", "BADCODE")

        assert not AgentConfig.is_enrolled()

    def test_server_unreachable_connect_error(self, work_dir: Path, monkeypatch) -> None:
        def _raise(*a, **kw):
            raise httpx.ConnectError("Connection refused")

        monkeypatch.setattr(httpx, "post", _raise)

        with pytest.raises(EnrollmentError, match="Serveur injoignable"):
            enroll("https://server:8000", "ABCD1234")

    def test_server_timeout(self, work_dir: Path, monkeypatch) -> None:
        def _raise(*a, **kw):
            raise httpx.TimeoutException("timed out")

        monkeypatch.setattr(httpx, "post", _raise)

        with pytest.raises(EnrollmentError, match="Serveur injoignable.*timeout"):
            enroll("https://server:8000", "ABCD1234")

    def test_rate_limited_429(self, work_dir: Path, monkeypatch) -> None:
        resp = _mock_response(429, {"detail": "Rate limited"})
        monkeypatch.setattr(httpx, "post", lambda *a, **kw: resp)

        with pytest.raises(EnrollmentError, match="Trop de tentatives"):
            enroll("https://server:8000", "ABCD1234")

    def test_server_error_500(self, work_dir: Path, monkeypatch) -> None:
        resp = _mock_response(500, {"detail": "Internal error"})
        monkeypatch.setattr(httpx, "post", lambda *a, **kw: resp)

        with pytest.raises(EnrollmentError, match="Erreur serveur.*500"):
            enroll("https://server:8000", "ABCD1234")

    def test_incomplete_response(self, work_dir: Path, monkeypatch) -> None:
        resp = _mock_response(200, {"agent_uuid": "", "agent_token": ""})
        monkeypatch.setattr(httpx, "post", lambda *a, **kw: resp)

        with pytest.raises(EnrollmentError, match="incomplète"):
            enroll("https://server:8000", "ABCD1234")

    def test_no_files_on_error(self, work_dir: Path, monkeypatch) -> None:
        """Aucun fichier ne doit rester après une erreur."""
        resp = _mock_response(400, {"detail": "bad"})
        monkeypatch.setattr(httpx, "post", lambda *a, **kw: resp)

        with pytest.raises(EnrollmentError):
            enroll("https://server:8000", "BADCODE")

        assert not (work_dir / "agent.json").exists()
        assert not (work_dir / "certs" / "agent.pem").exists()
        assert not (work_dir / "certs" / "agent.key").exists()


# ── Tests CLI ────────────────────────────────────────────────────────


class TestEnrollCLI:
    """Tests d'intégration CLI pour la commande enroll."""

    def test_already_enrolled_asks_confirmation(self, work_dir: Path, monkeypatch) -> None:
        """Si l'agent est déjà enrollé, demande confirmation."""
        monkeypatch.setattr(httpx, "post", lambda *a, **kw: _mock_response())
        # Premier enrollment
        enroll("https://server:8000", "ABCD1234", agent_name="PC-Test")

        # Deuxième tentative via CLI — répondre "n"
        runner = CliRunner()
        result = runner.invoke(cli, ["enroll", "--server", "https://server:8000", "--code", "NEWCODE"], input="n\n")
        assert result.exit_code == 0
        assert "Abandon" in result.output

    def test_reenroll_with_confirmation(self, work_dir: Path, monkeypatch) -> None:
        """Ré-enrollment après confirmation 'o'."""
        monkeypatch.setattr(httpx, "post", lambda *a, **kw: _mock_response())
        # Premier enrollment
        enroll("https://server:8000", "ABCD1234", agent_name="PC-Test")

        # Deuxième tentative via CLI — répondre "y"
        runner = CliRunner()
        result = runner.invoke(
            cli,
            ["enroll", "--server", "https://server:8000", "--code", "NEWCODE"],
            input="y\n",
        )
        assert result.exit_code == 0
        assert "Enrollment réussi" in result.output

    def test_enroll_error_displayed(self, work_dir: Path, monkeypatch) -> None:
        def _raise(*a, **kw):
            raise httpx.ConnectError("Connection refused")

        monkeypatch.setattr(httpx, "post", _raise)

        runner = CliRunner()
        result = runner.invoke(cli, ["enroll", "--server", "https://bad:8000", "--code", "ABCD1234"])
        assert result.exit_code != 0
        assert "Serveur injoignable" in result.output


# ── Tests sécurité ───────────────────────────────────────────────────


class TestEnrollSecurity:
    """Vérifications de sécurité de l'enrollment."""

    def test_enrollment_code_not_in_logs(self, work_dir: Path, monkeypatch, caplog) -> None:
        """Le code d'enrollment ne doit JAMAIS apparaître dans les logs."""
        secret_code = "SECRETX1"
        monkeypatch.setattr(httpx, "post", lambda *a, **kw: _mock_response())

        with caplog.at_level(logging.DEBUG):
            enroll("https://server:8000", secret_code, agent_name="PC-Test")

        all_logs = caplog.text
        assert secret_code not in all_logs

    def test_verify_false_on_first_call(self, work_dir: Path, monkeypatch) -> None:
        """Sans --ca-cert, le premier appel doit utiliser verify=False."""
        captured_kwargs: dict = {}

        def capture_post(*args, **kwargs):
            captured_kwargs.update(kwargs)
            return _mock_response()

        monkeypatch.setattr(httpx, "post", capture_post)
        enroll("https://server:8000", "ABCD1234")

        assert captured_kwargs.get("verify") is False

    def test_verify_with_ca_cert(self, work_dir: Path, monkeypatch) -> None:
        """Avec --ca-cert, le premier appel utilise le CA cert pour vérifier."""
        ca_path = work_dir / "my-ca.pem"
        ca_path.write_text("-----BEGIN CERTIFICATE-----\nCA...\n-----END CERTIFICATE-----\n")

        captured_kwargs: dict = {}

        def capture_post(*args, **kwargs):
            captured_kwargs.update(kwargs)
            return _mock_response()

        monkeypatch.setattr(httpx, "post", capture_post)
        enroll("https://server:8000", "ABCD1234", ca_cert_path=str(ca_path))

        assert captured_kwargs.get("verify") == str(ca_path)

    def test_sends_correct_body(self, work_dir: Path, monkeypatch) -> None:
        """Vérifie que le body envoyé correspond au schema EnrollRequest du serveur."""
        captured_kwargs: dict = {}

        def capture_post(*args, **kwargs):
            captured_kwargs.update(kwargs)
            return _mock_response()

        monkeypatch.setattr(httpx, "post", capture_post)
        enroll("https://server:8000", "MYCODE99")

        assert captured_kwargs["json"] == {"enrollment_code": "MYCODE99"}

    def test_timeout_is_set(self, work_dir: Path, monkeypatch) -> None:
        """Vérifie que le timeout est bien configuré."""
        captured_kwargs: dict = {}

        def capture_post(*args, **kwargs):
            captured_kwargs.update(kwargs)
            return _mock_response()

        monkeypatch.setattr(httpx, "post", capture_post)
        enroll("https://server:8000", "ABCD1234")

        assert captured_kwargs["timeout"] == ENROLL_TIMEOUT
