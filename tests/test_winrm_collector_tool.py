"""Tests pour l'outil WinRM collector."""

from __future__ import annotations

import logging
from unittest.mock import AsyncMock, patch

import pytest

from assistant_audit_agent.tools.winrm_collector_tool import (
    WinRMCollectResult,
    WinRMCollectorTool,
    collect_via_winrm,
)


VALID_PARAMS = {
    "host": "win01.corp.local",
    "username": "administrator",
    "password": "secret123",
    "port": 5986,
    "use_ssl": True,
    "transport": "ntlm",
}


class TestWinRMCollectorProperties:
    def test_name(self) -> None:
        assert WinRMCollectorTool().name == "winrm-collect"

    def test_timeout(self) -> None:
        assert WinRMCollectorTool().default_timeout == 1800


class TestWinRMCollectorValidation:

    @pytest.mark.asyncio
    async def test_invalid_host(self) -> None:
        tool = WinRMCollectorTool()
        params = {**VALID_PARAMS, "host": "win01; rm -rf"}
        result = await tool.execute("task-1", params)
        assert not result.success
        assert "host invalide" in result.error

    @pytest.mark.asyncio
    async def test_missing_password(self) -> None:
        tool = WinRMCollectorTool()
        params = {**VALID_PARAMS, "password": ""}
        result = await tool.execute("task-1", params)
        assert not result.success
        assert "password" in result.error

    @pytest.mark.asyncio
    async def test_invalid_username(self) -> None:
        tool = WinRMCollectorTool()
        params = {**VALID_PARAMS, "username": ""}
        result = await tool.execute("task-1", params)
        assert not result.success
        assert "username" in result.error

    @pytest.mark.asyncio
    async def test_invalid_transport(self) -> None:
        tool = WinRMCollectorTool()
        params = {**VALID_PARAMS, "transport": "evil_proto"}
        result = await tool.execute("task-1", params)
        assert not result.success
        assert "transport invalide" in result.error

    @pytest.mark.asyncio
    async def test_port_out_of_range(self) -> None:
        tool = WinRMCollectorTool()
        params = {**VALID_PARAMS, "port": -1}
        result = await tool.execute("task-1", params)
        assert not result.success
        assert "port" in result.error


class TestWinRMCollectorExecution:

    @pytest.mark.asyncio
    async def test_successful_run(self) -> None:
        tool = WinRMCollectorTool()

        def fake_collect(*args, **kwargs):
            return WinRMCollectResult(
                success=True,
                hostname="WIN01",
                os_info={"caption": "Windows Server 2022"},
            )

        on_progress = AsyncMock()

        with patch(
            "assistant_audit_agent.tools.winrm_collector_tool.collect_via_winrm",
            side_effect=fake_collect,
        ):
            result = await tool.execute("task-1", VALID_PARAMS, on_progress=on_progress)

        assert result.success
        assert result.output["hostname"] == "WIN01"
        assert on_progress.await_count >= 1

    @pytest.mark.asyncio
    async def test_collect_failure_returned_as_error(self) -> None:
        tool = WinRMCollectorTool()

        def fake_collect(*args, **kwargs):
            return WinRMCollectResult(
                success=False, error="WinRM: authentification refusée"
            )

        with patch(
            "assistant_audit_agent.tools.winrm_collector_tool.collect_via_winrm",
            side_effect=fake_collect,
        ):
            result = await tool.execute("task-1", VALID_PARAMS)

        assert not result.success
        assert "authentification" in result.error

    @pytest.mark.asyncio
    async def test_cancel_sets_flag(self) -> None:
        tool = WinRMCollectorTool()
        await tool.cancel()
        assert tool._cancelled is True


class TestTLSHardening:
    """Vérifie le durcissement TLS (différence vs collecteur serveur)."""

    def test_validate_by_default(self) -> None:
        """Par défaut : use_ssl=True, cert_validation='validate'."""
        with patch(
            "assistant_audit_agent.tools.winrm_collector_tool.winrm.Session"
        ) as mock_session:
            mock_session.return_value.run_ps.return_value.std_out = b""
            mock_session.return_value.run_ps.return_value.std_err = b""
            mock_session.return_value.run_ps.return_value.status_code = 0

            collect_via_winrm(
                host="win01.corp.local",
                username="admin",
                password="secret",
                port=5986,
                use_ssl=True,
                transport="ntlm",
                insecure_tls=False,
                progress_cb=lambda p, m: None,
            )

            # L'appel winrm.Session doit porter server_cert_validation="validate"
            _, kwargs = mock_session.call_args
            assert kwargs.get("server_cert_validation") == "validate"

    def test_insecure_tls_opts_out(self, caplog) -> None:
        """insecure_tls=True désactive la validation et log un avertissement."""
        with patch(
            "assistant_audit_agent.tools.winrm_collector_tool.winrm.Session"
        ) as mock_session:
            mock_session.return_value.run_ps.return_value.std_out = b""
            mock_session.return_value.run_ps.return_value.std_err = b""
            mock_session.return_value.run_ps.return_value.status_code = 0

            with caplog.at_level(logging.WARNING, logger="winrm_collector"):
                collect_via_winrm(
                    host="win01.corp.local",
                    username="admin",
                    password="secret",
                    port=5986,
                    use_ssl=True,
                    transport="ntlm",
                    insecure_tls=True,
                    progress_cb=lambda p, m: None,
                )

            _, kwargs = mock_session.call_args
            assert kwargs.get("server_cert_validation") == "ignore"
            assert any("insecure_tls" in rec.message or "MITM" in rec.message
                       for rec in caplog.records)

    def test_http_logs_warning(self, caplog) -> None:
        """use_ssl=False log un avertissement (connexion en clair)."""
        with patch(
            "assistant_audit_agent.tools.winrm_collector_tool.winrm.Session"
        ) as mock_session:
            mock_session.return_value.run_ps.return_value.std_out = b""
            mock_session.return_value.run_ps.return_value.std_err = b""
            mock_session.return_value.run_ps.return_value.status_code = 0

            with caplog.at_level(logging.WARNING, logger="winrm_collector"):
                collect_via_winrm(
                    host="win01.corp.local",
                    username="admin",
                    password="secret",
                    port=5985,
                    use_ssl=False,
                    transport="ntlm",
                    insecure_tls=False,
                    progress_cb=lambda p, m: None,
                )

            assert any("clair" in rec.message.lower() or "http" in rec.message.lower()
                       for rec in caplog.records)
