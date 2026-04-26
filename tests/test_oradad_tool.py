"""Tests pour l'outil ORADAD."""

from __future__ import annotations

from pathlib import Path
from unittest.mock import AsyncMock, MagicMock, patch

import pytest

from assistant_audit_agent.tools.oradad_tool import (
    OradadTool,
    _build_summary,
    _collect_artifacts,
    _resolve_oradad_path,
)

SAMPLE_CONFIG_XML = """<?xml version="1.0" encoding="UTF-8"?>
<ORADAD>
  <General>
    <AutoGetDomain>false</AutoGetDomain>
    <Level>4</Level>
  </General>
  <Domains>
    <Domain>
      <Server>dc01.corp.local</Server>
      <Port>389</Port>
      <DomainName>corp.local</DomainName>
      <User>admin</User>
      <UserDomain>CORP</UserDomain>
      <Password>secret123</Password>
    </Domain>
  </Domains>
</ORADAD>"""


class TestOradadProperties:
    def test_name(self) -> None:
        assert OradadTool().name == "oradad"

    def test_timeout(self) -> None:
        assert OradadTool().default_timeout == 7200


class TestOradadValidation:

    @pytest.mark.asyncio
    async def test_missing_config_xml(self) -> None:
        tool = OradadTool()
        result = await tool.execute("task-1", {})
        assert not result.success
        assert "config_xml" in result.error

    @pytest.mark.asyncio
    async def test_oradad_not_found(self) -> None:
        tool = OradadTool()
        with patch(
            "assistant_audit_agent.tools.oradad_tool._resolve_oradad_path",
            return_value=None,
        ):
            result = await tool.execute("task-1", {"config_xml": SAMPLE_CONFIG_XML})
        assert not result.success
        assert "introuvable" in result.error


class TestOradadExecution:

    @pytest.mark.asyncio
    async def test_successful_run(self, tmp_path: Path) -> None:
        tool = OradadTool()

        async def fake_subprocess(*args, **kwargs):
            proc = AsyncMock()
            proc.returncode = 0
            proc.stdout = AsyncMock()
            proc.stdout.readline = AsyncMock(return_value=b"")
            proc.stderr = AsyncMock()
            proc.stderr.read = AsyncMock(return_value=b"")
            proc.wait = AsyncMock()

            # Creer des artifacts dans le work_dir
            cwd = kwargs.get("cwd", "")
            if cwd:
                (Path(cwd) / "corp.local").mkdir(exist_ok=True)
                (Path(cwd) / "corp.local" / "users.tsv").write_text("data", encoding="utf-8")
                (Path(cwd) / "output.tar").write_bytes(b"fake tar")
            return proc

        on_progress = AsyncMock()

        with patch(
            "assistant_audit_agent.tools.oradad_tool._resolve_oradad_path",
            return_value=Path("C:/tools/ORADAD.exe"),
        ):
            with patch("asyncio.create_subprocess_exec", side_effect=fake_subprocess):
                result = await tool.execute(
                    "task-1",
                    {"config_xml": SAMPLE_CONFIG_XML},
                    on_progress=on_progress,
                )

        assert result.success
        assert result.output["files_count"] >= 1
        assert "corp.local" in result.output["domains_collected"]

    @pytest.mark.asyncio
    async def test_nonzero_exit_code(self) -> None:
        tool = OradadTool()

        async def fake_subprocess(*args, **kwargs):
            proc = AsyncMock()
            proc.returncode = 1
            proc.stdout = AsyncMock()
            proc.stdout.readline = AsyncMock(return_value=b"")
            proc.stderr = AsyncMock()
            proc.stderr.read = AsyncMock(return_value=b"Access denied\n")
            proc.wait = AsyncMock()
            return proc

        with patch(
            "assistant_audit_agent.tools.oradad_tool._resolve_oradad_path",
            return_value=Path("C:/tools/ORADAD.exe"),
        ):
            with patch("asyncio.create_subprocess_exec", side_effect=fake_subprocess):
                result = await tool.execute("task-1", {"config_xml": SAMPLE_CONFIG_XML})

        assert not result.success
        assert "Access denied" in result.error

    @pytest.mark.asyncio
    async def test_cancel_kills_process(self) -> None:
        tool = OradadTool()
        mock_proc = MagicMock()
        tool._process = mock_proc
        await tool.cancel()
        mock_proc.kill.assert_called_once()

    @pytest.mark.asyncio
    async def test_config_file_cleaned_after_run(self, tmp_path: Path) -> None:
        """Le fichier config (avec credentials) doit etre supprime."""
        tool = OradadTool()

        async def fake_subprocess(*args, **kwargs):
            proc = AsyncMock()
            proc.returncode = 0
            proc.stdout = AsyncMock()
            proc.stdout.readline = AsyncMock(return_value=b"")
            proc.stderr = AsyncMock()
            proc.stderr.read = AsyncMock(return_value=b"")
            proc.wait = AsyncMock()
            return proc

        with patch(
            "assistant_audit_agent.tools.oradad_tool._resolve_oradad_path",
            return_value=Path("C:/tools/ORADAD.exe"),
        ):
            with patch("asyncio.create_subprocess_exec", side_effect=fake_subprocess):
                await tool.execute("task-1", {"config_xml": SAMPLE_CONFIG_XML})

        # Le fichier config ne doit plus exister
        assert tool._config_file is None


class TestResolveOradadPath:

    def test_unsafe_path_rejected(self) -> None:
        assert _resolve_oradad_path("C:/tools; rm -rf /") is None

    def test_absolute_path_exists(self, tmp_path: Path) -> None:
        fake_exe = tmp_path / "ORADAD.exe"
        fake_exe.write_text("fake", encoding="utf-8")
        result = _resolve_oradad_path(str(fake_exe))
        assert result == fake_exe

    def test_which_fallback(self) -> None:
        with patch("shutil.which", return_value="C:/tools/ORADAD.exe"):
            result = _resolve_oradad_path("ORADAD.exe")
        assert result == Path("C:/tools/ORADAD.exe")

    def test_not_found(self) -> None:
        with patch("shutil.which", return_value=None):
            assert _resolve_oradad_path("ORADAD.exe") is None


class TestArtifacts:

    def test_collect_artifacts(self, tmp_path: Path) -> None:
        (tmp_path / "output.tar").write_bytes(b"tar")
        (tmp_path / "users.tsv").write_text("data", encoding="utf-8")
        (tmp_path / "other.txt").write_text("skip", encoding="utf-8")

        artifacts = _collect_artifacts(tmp_path)
        names = {a.name for a in artifacts}
        assert "output.tar" in names
        assert "users.tsv" in names
        assert "other.txt" not in names

    def test_build_summary(self, tmp_path: Path) -> None:
        (tmp_path / "corp.local").mkdir()
        (tmp_path / "corp.local" / "data.tsv").write_text("x", encoding="utf-8")
        artifacts = [tmp_path / "corp.local" / "data.tsv"]
        summary = _build_summary(tmp_path, artifacts)
        assert "corp.local" in summary["domains_collected"]
        assert summary["files_count"] == 1
        assert summary["total_size_bytes"] > 0
