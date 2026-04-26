"""Tests pour l'outil SSH collector."""

from __future__ import annotations

import inspect
import re
from unittest.mock import AsyncMock, patch

import pytest

from assistant_audit_agent.tools.ssh_collector_tool import (
    SSHCollectResult,
    SshCollectorTool,
    _parse_ssh_results,
)


VALID_PARAMS = {
    "host": "192.168.1.10",
    "port": 22,
    "username": "root",
    "password": "secret",
    "device_profile": "linux_server",
}


class TestSshCollectorProperties:
    def test_name(self) -> None:
        assert SshCollectorTool().name == "ssh-collect"

    def test_timeout(self) -> None:
        assert SshCollectorTool().default_timeout == 1800


class TestSshCollectorValidation:

    @pytest.mark.asyncio
    async def test_invalid_host(self) -> None:
        tool = SshCollectorTool()
        params = {**VALID_PARAMS, "host": "192.168.1.10; rm -rf /"}
        result = await tool.execute("task-1", params)
        assert not result.success
        assert "host invalide" in result.error

    @pytest.mark.asyncio
    async def test_empty_host(self) -> None:
        tool = SshCollectorTool()
        params = {**VALID_PARAMS, "host": ""}
        result = await tool.execute("task-1", params)
        assert not result.success
        assert "host invalide" in result.error

    @pytest.mark.asyncio
    async def test_invalid_username(self) -> None:
        tool = SshCollectorTool()
        params = {**VALID_PARAMS, "username": "root; id"}
        result = await tool.execute("task-1", params)
        assert not result.success
        assert "username invalide" in result.error

    @pytest.mark.asyncio
    async def test_port_out_of_range(self) -> None:
        tool = SshCollectorTool()
        params = {**VALID_PARAMS, "port": 70000}
        result = await tool.execute("task-1", params)
        assert not result.success
        assert "port hors plage" in result.error

    @pytest.mark.asyncio
    async def test_unsupported_profile(self) -> None:
        tool = SshCollectorTool()
        params = {**VALID_PARAMS, "device_profile": "cisco_asa"}
        result = await tool.execute("task-1", params)
        assert not result.success
        assert "device_profile non supporté" in result.error

    @pytest.mark.asyncio
    async def test_missing_auth(self) -> None:
        tool = SshCollectorTool()
        params = {**VALID_PARAMS}
        params.pop("password")
        result = await tool.execute("task-1", params)
        assert not result.success
        assert "password" in result.error or "private_key" in result.error

    @pytest.mark.asyncio
    async def test_private_key_accepted(self) -> None:
        """Une clé privée suffit — pas besoin de password."""
        tool = SshCollectorTool()
        params = {**VALID_PARAMS, "private_key": "-----BEGIN KEY-----\nxxx\n-----END KEY-----"}
        params.pop("password")

        async def fake_collect(*args, **kwargs):
            return SSHCollectResult(success=True, hostname="host1")

        with patch(
            "assistant_audit_agent.tools.ssh_collector_tool.collect_via_ssh",
            side_effect=lambda *a, **k: SSHCollectResult(success=True, hostname="host1"),
        ):
            result = await tool.execute("task-1", params)

        assert result.success


class TestSshCollectorExecution:

    @pytest.mark.asyncio
    async def test_successful_run(self) -> None:
        tool = SshCollectorTool()

        def fake_collect(host, port, username, password, private_key, passphrase,
                         device_profile, progress_cb):
            progress_cb(50, "commande test")
            return SSHCollectResult(
                success=True,
                hostname="srv01",
                os_info={"kernel": "6.1.0"},
            )

        on_progress = AsyncMock()

        with patch(
            "assistant_audit_agent.tools.ssh_collector_tool.collect_via_ssh",
            side_effect=fake_collect,
        ):
            result = await tool.execute("task-1", VALID_PARAMS, on_progress=on_progress)

        assert result.success
        assert result.output["hostname"] == "srv01"
        assert result.output["os_info"]["kernel"] == "6.1.0"
        assert on_progress.await_count >= 1

    @pytest.mark.asyncio
    async def test_collect_failure_returned_as_error(self) -> None:
        tool = SshCollectorTool()

        def fake_collect(*args, **kwargs):
            return SSHCollectResult(
                success=False, error="SSH: authentification refusée"
            )

        with patch(
            "assistant_audit_agent.tools.ssh_collector_tool.collect_via_ssh",
            side_effect=fake_collect,
        ):
            result = await tool.execute("task-1", VALID_PARAMS)

        assert not result.success
        assert "authentification" in result.error

    @pytest.mark.asyncio
    async def test_exception_returned_as_error(self) -> None:
        tool = SshCollectorTool()

        def fake_collect(*args, **kwargs):
            raise RuntimeError("boom")

        with patch(
            "assistant_audit_agent.tools.ssh_collector_tool.collect_via_ssh",
            side_effect=fake_collect,
        ):
            result = await tool.execute("task-1", VALID_PARAMS)

        assert not result.success
        assert "boom" in result.error

    @pytest.mark.asyncio
    async def test_cancel_sets_flag(self) -> None:
        tool = SshCollectorTool()
        await tool.cancel()
        assert tool._cancelled is True


class TestHostKeyPolicy:
    """Verifie la politique TOFU : pas d'AutoAddPolicy silencieuse, log du
    fingerprint sur premiere connexion, et la classe utilisee est bien
    une MissingHostKeyPolicy custom (pas RejectPolicy strict)."""

    def test_no_silent_autoadd_policy(self) -> None:
        from assistant_audit_agent.tools import ssh_collector_tool

        src = inspect.getsource(ssh_collector_tool.collect_via_ssh)
        # AutoAddPolicy ajouterait silencieusement la cle sans log : interdit
        assert "AutoAddPolicy" not in src
        # On veut bien une politique custom de type MissingHostKeyPolicy
        assert "MissingHostKeyPolicy" in src
        # Et un log explicite du fingerprint pour traçabilite
        assert "fingerprint" in src

    def test_policy_subclasses_missing_host_key_policy(self) -> None:
        """La politique custom doit declarer hériter de MissingHostKeyPolicy."""
        from assistant_audit_agent.tools import ssh_collector_tool

        src = inspect.getsource(ssh_collector_tool.collect_via_ssh)
        # Une classe TOFU heritant de MissingHostKeyPolicy doit etre presente
        assert re.search(
            r"class\s+_LogAndAccept\s*\(\s*paramiko\.MissingHostKeyPolicy\s*\)\s*:",
            src,
        ), "_LogAndAccept doit heriter de paramiko.MissingHostKeyPolicy"
        # Et le commentaire/log doit mentionner TOFU pour expliciter l'intention
        assert "TOFU" in src


class TestParseSshResults:

    def test_linux_os_info_from_os_release(self) -> None:
        result = SSHCollectResult()
        raw = {
            "hostname": "srv01",
            "os_release": (
                'NAME="Debian GNU/Linux"\n'
                'VERSION_ID="12"\n'
            ),
            "kernel": "6.1.0",
            "arch": "x86_64",
        }
        _parse_ssh_results(result, raw)
        assert result.hostname == "srv01"
        assert result.os_info.get("kernel") == "6.1.0"
        assert result.os_info.get("arch") == "x86_64"
