"""Tests pour le CLI Click (parsing des commandes)."""

from __future__ import annotations

from click.testing import CliRunner

from assistant_audit_agent.main import cli


@classmethod
def runner() -> CliRunner:
    return CliRunner()


class TestCLICommands:
    """Vérifie que les commandes CLI parsent correctement."""

    def test_version(self) -> None:
        result = CliRunner().invoke(cli, ["version"])
        assert result.exit_code == 0
        assert "assistant-audit-agent v" in result.output

    def test_status_not_enrolled(self, tmp_path, monkeypatch) -> None:
        monkeypatch.chdir(tmp_path)
        result = CliRunner().invoke(cli, ["status"])
        assert result.exit_code == 0
        assert "non enrôlé" in result.output

    def test_enroll_requires_options(self) -> None:
        result = CliRunner().invoke(cli, ["enroll"])
        assert result.exit_code != 0
        assert "Missing option" in result.output or "required" in result.output.lower()

    def test_start_not_enrolled(self, tmp_path, monkeypatch) -> None:
        monkeypatch.chdir(tmp_path)
        result = CliRunner().invoke(cli, ["start"])
        assert result.exit_code != 0

    def test_install_service_placeholder(self) -> None:
        result = CliRunner().invoke(cli, ["install-service"])
        assert result.exit_code == 0

    def test_help(self) -> None:
        result = CliRunner().invoke(cli, ["--help"])
        assert result.exit_code == 0
        assert "enroll" in result.output
        assert "start" in result.output
        assert "status" in result.output
        assert "version" in result.output
