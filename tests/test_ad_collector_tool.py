"""Tests pour l'outil AD collector."""

from __future__ import annotations

import json
from pathlib import Path
from unittest.mock import AsyncMock, MagicMock, patch

import pytest

from assistant_audit_agent.tools.ad_collector_tool import (
    ADCollectorTool,
    _build_ps_script,
    _parse_output,
)


VALID_PARAMS = {
    "target_host": "dc01.corp.local",
    "target_port": 389,
    "use_ssl": False,
    "username": "admin",
    "password": "secret123",
    "domain": "corp.local",
    "auth_method": "ntlm",
}


class TestADCollectorProperties:
    def test_name(self) -> None:
        assert ADCollectorTool().name == "ad_collector"

    def test_timeout(self) -> None:
        assert ADCollectorTool().default_timeout == 3600


class TestADCollectorValidation:

    @pytest.mark.asyncio
    async def test_invalid_target_host(self) -> None:
        tool = ADCollectorTool()
        params = {**VALID_PARAMS, "target_host": "dc01; rm -rf /"}
        result = await tool.execute("task-1", params)
        assert not result.success
        assert "target_host invalide" in result.error

    @pytest.mark.asyncio
    async def test_empty_target_host(self) -> None:
        tool = ADCollectorTool()
        params = {**VALID_PARAMS, "target_host": ""}
        result = await tool.execute("task-1", params)
        assert not result.success
        assert "target_host invalide" in result.error

    @pytest.mark.asyncio
    async def test_invalid_domain(self) -> None:
        tool = ADCollectorTool()
        params = {**VALID_PARAMS, "domain": "corp.local; evil"}
        result = await tool.execute("task-1", params)
        assert not result.success
        assert "domain invalide" in result.error

    @pytest.mark.asyncio
    async def test_missing_username(self) -> None:
        tool = ADCollectorTool()
        params = {**VALID_PARAMS, "username": ""}
        result = await tool.execute("task-1", params)
        assert not result.success
        assert "username" in result.error


class TestADCollectorExecution:

    @pytest.mark.asyncio
    async def test_successful_run(self, tmp_path: Path) -> None:
        tool = ADCollectorTool()

        async def fake_subprocess(*args, **kwargs):
            proc = AsyncMock()
            proc.returncode = 0

            lines = [b"Connexion a dc01...\n", b"Resultats ecrits\n", b""]
            idx = {"i": -1}

            async def readline():
                idx["i"] += 1
                return lines[idx["i"]] if idx["i"] < len(lines) else b""

            proc.stdout = AsyncMock()
            proc.stdout.readline = readline
            proc.stderr = AsyncMock()
            proc.stderr.read = AsyncMock(return_value=b"")
            proc.wait = AsyncMock()

            # Ecrire la sortie JSON dans le fichier temporaire
            # Le script PS ecrit dans output_path - simuler
            # On recupere le path depuis les args du script
            cmd_args = list(args)
            for i, a in enumerate(cmd_args):
                if a == "-Command" and i + 1 < len(cmd_args):
                    script = cmd_args[i + 1]
                    # Extraire outputPath du script
                    import re
                    m = re.search(r"\$outputPath = '([^']+)'", script)
                    if m:
                        Path(m.group(1)).write_text(
                            json.dumps({"domain_name": "corp.local", "status": "completed"}),
                            encoding="utf-8",
                        )
            return proc

        on_progress = AsyncMock()

        with patch("asyncio.create_subprocess_exec", side_effect=fake_subprocess):
            result = await tool.execute("task-1", VALID_PARAMS, on_progress=on_progress)

        assert result.success
        assert result.output.get("domain_name") == "corp.local"
        assert on_progress.await_count >= 1

        for a in result.artifacts:
            a.unlink(missing_ok=True)

    @pytest.mark.asyncio
    async def test_nonzero_exit_code(self) -> None:
        tool = ADCollectorTool()

        async def fake_subprocess(*args, **kwargs):
            proc = AsyncMock()
            proc.returncode = 1
            proc.stdout = AsyncMock()
            proc.stdout.readline = AsyncMock(return_value=b"")
            proc.stderr = AsyncMock()
            proc.stderr.read = AsyncMock(return_value=b"LDAP bind failed\n")
            proc.wait = AsyncMock()
            return proc

        with patch("asyncio.create_subprocess_exec", side_effect=fake_subprocess):
            result = await tool.execute("task-1", VALID_PARAMS)

        assert not result.success
        assert "LDAP bind failed" in result.error

    @pytest.mark.asyncio
    async def test_powershell_not_found(self) -> None:
        tool = ADCollectorTool()

        with patch("asyncio.create_subprocess_exec", side_effect=FileNotFoundError):
            result = await tool.execute("task-1", VALID_PARAMS)

        assert not result.success
        assert "powershell" in result.error.lower()

    @pytest.mark.asyncio
    async def test_cancel_kills_process(self) -> None:
        tool = ADCollectorTool()
        mock_proc = MagicMock()
        tool._process = mock_proc
        await tool.cancel()
        mock_proc.kill.assert_called_once()


class TestPSScript:

    def test_credentials_via_env(self) -> None:
        script = _build_ps_script("dc01", 389, False, "corp.local", "ntlm", "out.json")
        assert "$env:AD_USERNAME" in script
        assert "$env:AD_PASSWORD" in script
        # Credentials ne doivent PAS etre en clair dans le script
        assert "secret" not in script

    def test_ldaps_protocol(self) -> None:
        script = _build_ps_script("dc01", 636, True, "corp.local", "ntlm", "out.json")
        assert "LDAPS" in script

    def test_target_in_script(self) -> None:
        script = _build_ps_script("dc01.corp.local", 389, False, "corp.local", "ntlm", "out.json")
        assert "dc01.corp.local" in script
        assert "corp.local" in script


class TestParseOutput:

    def test_valid_json(self, tmp_path: Path) -> None:
        f = tmp_path / "output.json"
        f.write_text(json.dumps({"domain": "corp.local"}), encoding="utf-8")
        result = _parse_output(f)
        assert result["domain"] == "corp.local"

    def test_missing_file(self, tmp_path: Path) -> None:
        result = _parse_output(tmp_path / "missing.json")
        assert "error" in result

    def test_invalid_json(self, tmp_path: Path) -> None:
        f = tmp_path / "bad.json"
        f.write_text("not json", encoding="utf-8")
        result = _parse_output(f)
        assert "error" in result

    def test_utf8_bom(self, tmp_path: Path) -> None:
        """PowerShell ecrit souvent en UTF-8 avec BOM."""
        f = tmp_path / "bom.json"
        content = json.dumps({"ok": True})
        f.write_bytes(b"\xef\xbb\xbf" + content.encode("utf-8"))
        result = _parse_output(f)
        assert result["ok"] is True
