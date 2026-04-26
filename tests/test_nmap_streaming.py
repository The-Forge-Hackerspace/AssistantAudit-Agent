"""Tests pour le streaming de progression nmap vers le serveur via WebSocket.

Couvre :
    - nmap_tool injecte --stats-every 5s + -v dans ses args
    - nmap_tool parse "XX.XX% done" et appelle on_progress() avec dedup
    - output_lines cape a MAX_OUTPUT_LINES_PER_MESSAGE (20)
    - task_runner transmet on_progress au WebSocket client avec le bon schema
    - Throttle 5s respecte (pas plus d'un message toutes les 5 secondes)
    - Filtrage des credentials (password=, pwd=, secret=, token=)
"""

from __future__ import annotations

import asyncio
from pathlib import Path
from unittest.mock import AsyncMock, patch

import pytest

from assistant_audit_agent.task_runner import (
    PROGRESS_THROTTLE_SECONDS,
    TaskRunner,
    _CREDENTIAL_PATTERN,
)
from assistant_audit_agent.tools import ToolBase, ToolResult
from assistant_audit_agent.tools.nmap_tool import (
    MAX_OUTPUT_LINES_PER_MESSAGE,
    NMAP_STATS_INTERVAL,
    NmapTool,
    _PROGRESS_PATTERN,
)


# ── Helpers ──────────────────────────────────────────────────────────


def _make_fake_subprocess(
    lines: list[bytes],
    returncode: int = 0,
    xml: str | None = None,
    captured_args: list[list[str]] | None = None,
):
    """Cree un fake create_subprocess_exec qui stream les lignes donnees."""

    async def factory(*args, **kwargs):
        if captured_args is not None:
            captured_args.append(list(args))
        proc = AsyncMock()
        proc.returncode = returncode
        idx = {"i": -1}

        async def readline():
            idx["i"] += 1
            return lines[idx["i"]] if idx["i"] < len(lines) else b""

        proc.stdout = AsyncMock()
        proc.stdout.readline = readline
        proc.stderr = AsyncMock()
        proc.stderr.read = AsyncMock(return_value=b"")
        proc.wait = AsyncMock()

        # Ecrire le XML dans le fichier de sortie si demande
        cmd_args = list(args)
        for i, a in enumerate(cmd_args):
            if a == "-oX" and i + 1 < len(cmd_args):
                content = xml or (
                    '<?xml version="1.0"?><nmaprun><runstats>'
                    '<finished elapsed="1"/><hosts up="0" down="0" total="0"/>'
                    '</runstats></nmaprun>'
                )
                Path(cmd_args[i + 1]).write_text(content)
        return proc

    return factory


class _FakeTool(ToolBase):
    """Outil factice pour tester le task_runner sans nmap."""

    def __init__(self, lines: list[str], delay_per_line: float = 0.0) -> None:
        self._lines = lines
        self._delay = delay_per_line

    @property
    def name(self) -> str:
        return "nmap"

    @property
    def default_timeout(self) -> int:
        return 60

    async def execute(self, task_id, parameters, on_progress=None):
        for i, line in enumerate(self._lines):
            if self._delay:
                await asyncio.sleep(self._delay)
            if on_progress is not None:
                await on_progress(int((i + 1) / len(self._lines) * 100), [line])
        return ToolResult(success=True, output={"hosts": []})

    async def cancel(self):
        pass


def _cleanup_artifacts(result: ToolResult) -> None:
    for a in result.artifacts:
        a.unlink(missing_ok=True)


# ── Tests parsing regex ─────────────────────────────────────────────


class TestProgressRegex:
    """Verifie que _PROGRESS_PATTERN capture bien les lignes nmap Stats."""

    @pytest.mark.parametrize("line,expected", [
        ("Stats: 0:01:23 elapsed; 0 hosts completed. 47.50% done; ETC: ...", "47.50"),
        ("Service scan Timing: About 12.34% done; ETC: 18:42 (0:00:35 remaining)", "12.34"),
        ("Parallel DNS resolution of 256 hosts. Timing: About 99.9% done", "99.9"),
        ("SYN Stealth Scan Timing: About 100.00% done", "100.00"),
        ("Starting Nmap 7.94", None),
        ("Discovered open port 22/tcp on 10.0.0.1", None),
    ])
    def test_pattern_matches(self, line: str, expected: str | None) -> None:
        m = _PROGRESS_PATTERN.search(line)
        if expected is None:
            assert m is None
        else:
            assert m is not None
            assert m.group(1) == expected

    def test_parsing_rounds_correctly(self) -> None:
        """47.50% → round(47.50) = 48 (banker's rounding mais 47.5 tombe sur 48)."""
        # round(47.50) avec banker's rounding → 48 (puisque 47.5 est arrondi au pair le plus proche)
        # En pratique round(47.5) = 48 en Python 3.
        m = _PROGRESS_PATTERN.search(
            "Stats: 0:01:23 elapsed; ... 47.50% done; ETC: ..."
        )
        assert m is not None
        value = round(float(m.group(1)))
        assert value == 48


# ── Tests nmap_tool : injection des flags ──────────────────────────


class TestNmapFlagInjection:
    """Verifie que --stats-every 5s et -v sont injectes dans les args nmap."""

    @pytest.mark.asyncio
    async def test_stats_every_flag_injected(self) -> None:
        """--stats-every 5s doit etre passe a nmap."""
        captured: list[list[str]] = []
        lines = [b""]

        tool = NmapTool()
        fake = _make_fake_subprocess(lines, captured_args=captured)

        with patch("assistant_audit_agent.tools.nmap_tool._nmap_available", return_value=True):
            with patch("asyncio.create_subprocess_exec", side_effect=fake):
                result = await tool.execute("task-1", {"target": "10.0.0.1"})

        assert result.success
        assert len(captured) == 1
        args = captured[0]
        assert "--stats-every" in args
        idx = args.index("--stats-every")
        assert args[idx + 1] == NMAP_STATS_INTERVAL == "5s"
        _cleanup_artifacts(result)

    @pytest.mark.asyncio
    async def test_verbose_flag_injected(self) -> None:
        """-v doit etre ajoute pour forcer l'emission des lignes Stats."""
        captured: list[list[str]] = []
        lines = [b""]

        tool = NmapTool()
        fake = _make_fake_subprocess(lines, captured_args=captured)

        with patch("assistant_audit_agent.tools.nmap_tool._nmap_available", return_value=True):
            with patch("asyncio.create_subprocess_exec", side_effect=fake):
                result = await tool.execute("task-1", {"target": "10.0.0.1"})

        assert result.success
        args = captured[0]
        assert "-v" in args or "-vv" in args
        _cleanup_artifacts(result)


# ── Tests nmap_tool : parsing + dedup + buffer ──────────────────────


class TestNmapProgressStreaming:
    """Verifie que nmap_tool appelle on_progress() sur les lignes Stats uniquement."""

    @pytest.mark.asyncio
    async def test_stats_line_triggers_on_progress(self) -> None:
        """Une ligne '47.50% done' produit un on_progress(48, [...])."""
        lines = [
            b"Starting Nmap 7.94\n",
            b"Scanning 10.0.0.0/24\n",
            b"Stats: 0:00:15 elapsed; 0 hosts completed. 47.50% done; ETC: ...\n",
            b"Discovered open port 22/tcp\n",
            b"",
        ]

        progress_calls: list[tuple[int, list[str]]] = []

        async def capture(progress: int, output_lines: list[str]) -> None:
            progress_calls.append((progress, output_lines))

        tool = NmapTool()
        fake = _make_fake_subprocess(lines)

        with patch("assistant_audit_agent.tools.nmap_tool._nmap_available", return_value=True):
            with patch("asyncio.create_subprocess_exec", side_effect=fake):
                result = await tool.execute(
                    "task-1", {"target": "10.0.0.0/24"}, on_progress=capture,
                )

        assert result.success
        assert len(progress_calls) == 1
        progress, lines_batch = progress_calls[0]
        assert progress == 48  # round(47.50) = 48
        # Le buffer doit inclure les lignes precedentes + la ligne Stats
        assert any("47.50% done" in ln for ln in lines_batch)
        _cleanup_artifacts(result)

    @pytest.mark.asyncio
    async def test_lines_without_progress_dont_emit(self) -> None:
        """Les lignes sans '% done' n'appellent pas on_progress."""
        lines = [
            b"Starting Nmap 7.94\n",
            b"Scanning 10.0.0.0/24\n",
            b"Discovered open port 22/tcp\n",
            b"Discovered open port 80/tcp\n",
            b"",
        ]

        progress_calls: list[tuple[int, list[str]]] = []

        async def capture(progress: int, output_lines: list[str]) -> None:
            progress_calls.append((progress, output_lines))

        tool = NmapTool()
        fake = _make_fake_subprocess(lines)

        with patch("assistant_audit_agent.tools.nmap_tool._nmap_available", return_value=True):
            with patch("asyncio.create_subprocess_exec", side_effect=fake):
                result = await tool.execute(
                    "task-1", {"target": "10.0.0.0/24"}, on_progress=capture,
                )

        assert result.success
        assert progress_calls == []
        _cleanup_artifacts(result)

    @pytest.mark.asyncio
    async def test_progress_dedup(self) -> None:
        """Deux lignes consecutives avec 47.50% ne produisent qu'un seul on_progress."""
        lines = [
            b"Starting Nmap 7.94\n",
            b"Stats: 0:00:15 elapsed; ... 47.50% done; ETC: ...\n",
            b"Stats: 0:00:20 elapsed; ... 47.50% done; ETC: ...\n",
            b"Stats: 0:00:25 elapsed; ... 60.00% done; ETC: ...\n",
            b"Stats: 0:00:30 elapsed; ... 60.00% done; ETC: ...\n",
            b"",
        ]

        progress_calls: list[tuple[int, list[str]]] = []

        async def capture(progress: int, output_lines: list[str]) -> None:
            progress_calls.append((progress, output_lines))

        tool = NmapTool()
        fake = _make_fake_subprocess(lines)

        with patch("assistant_audit_agent.tools.nmap_tool._nmap_available", return_value=True):
            with patch("asyncio.create_subprocess_exec", side_effect=fake):
                result = await tool.execute(
                    "task-1", {"target": "10.0.0.0/24"}, on_progress=capture,
                )

        assert result.success
        # 5 lignes Stats (dont 47.50 x2 puis 60.00 x2) → 2 valeurs distinctes = 2 envois
        progress_values = [p for p, _ in progress_calls]
        assert progress_values == [48, 60]
        _cleanup_artifacts(result)

    @pytest.mark.asyncio
    async def test_output_lines_capped_at_20(self) -> None:
        """Le buffer output_lines ne depasse jamais 20 lignes."""
        # Generer 50 lignes avant un Stats → le buffer doit etre cape a 20
        preamble = [f"Line number {i}\n".encode() for i in range(50)]
        stats = [b"Stats: 0:00:15 elapsed; ... 10.00% done; ETC: ...\n"]
        lines = preamble + stats + [b""]

        progress_calls: list[tuple[int, list[str]]] = []

        async def capture(progress: int, output_lines: list[str]) -> None:
            progress_calls.append((progress, output_lines))

        tool = NmapTool()
        fake = _make_fake_subprocess(lines)

        with patch("assistant_audit_agent.tools.nmap_tool._nmap_available", return_value=True):
            with patch("asyncio.create_subprocess_exec", side_effect=fake):
                result = await tool.execute(
                    "task-1", {"target": "10.0.0.0/24"}, on_progress=capture,
                )

        assert result.success
        assert len(progress_calls) == 1
        _, lines_batch = progress_calls[0]
        assert len(lines_batch) <= MAX_OUTPUT_LINES_PER_MESSAGE == 20

        _cleanup_artifacts(result)

    @pytest.mark.asyncio
    async def test_no_callback_still_works(self) -> None:
        """Execution sans on_progress ne plante pas meme avec des lignes Stats."""
        lines = [
            b"Starting Nmap\n",
            b"Stats: 0:00:15 elapsed; ... 50.00% done; ETC: ...\n",
            b"",
        ]
        tool = NmapTool()

        with patch("assistant_audit_agent.tools.nmap_tool._nmap_available", return_value=True):
            with patch("asyncio.create_subprocess_exec", side_effect=_make_fake_subprocess(lines)):
                result = await tool.execute("task-1", {"target": "10.0.0.1"})

        assert result.success
        _cleanup_artifacts(result)


# ── Tests task_runner : throttle 5s + schema JSON ───────────────────


class TestProgressThrottle:
    """Verifie que le throttle 5s est respecte dans task_runner."""

    def test_throttle_constant_is_5s(self) -> None:
        assert PROGRESS_THROTTLE_SECONDS == 5.0

    @pytest.mark.asyncio
    async def test_throttle_batches_lines(self) -> None:
        """Les lignes emises rapidement sont accumulees et envoyees en un batch."""
        ws_client = AsyncMock()
        ws_client.send = AsyncMock()

        runner = TaskRunner(ws_client, allowed_tools=["nmap"])
        # Outil qui emet 10 lignes sans delai (< 5s)
        tool = _FakeTool([f"line {i}" for i in range(10)])
        runner.register_tool(tool)

        await runner.handle_new_task("new_task", {
            "task_uuid": "uuid-1",
            "tool": "nmap",
            "parameters": {"target": "10.0.0.1"},
        })

        # Attendre l'execution
        assert runner._execution_task is not None
        await runner._execution_task

        # Compter les appels task_progress
        progress_calls = [
            c for c in ws_client.send.call_args_list
            if c.args[0] == "task_progress"
        ]

        # Avec 10 lignes emises instantanement, le throttle devrait
        # limiter a ~1-2 envois (premier immediat car delta >= 5s au debut,
        # puis le flush final)
        assert len(progress_calls) <= 3

    @pytest.mark.asyncio
    async def test_slow_lines_get_individual_sends(self) -> None:
        """Lignes espacees de plus de 5s sont envoyees individuellement."""
        ws_client = AsyncMock()
        ws_client.send = AsyncMock()

        runner = TaskRunner(ws_client, allowed_tools=["nmap"])

        # Simuler le throttle en patchant time.monotonic
        call_count = {"n": 0}

        def fake_monotonic():
            # Chaque appel a on_progress avance de 6 secondes
            call_count["n"] += 1
            return call_count["n"] * 6.0

        tool = _FakeTool(["line A", "line B", "line C"])
        runner.register_tool(tool)

        with patch("assistant_audit_agent.task_runner.time.monotonic", side_effect=fake_monotonic):
            await runner.handle_new_task("new_task", {
                "task_uuid": "uuid-2",
                "tool": "nmap",
                "parameters": {"target": "10.0.0.1"},
            })
            assert runner._execution_task is not None
            await runner._execution_task

        progress_calls = [
            c for c in ws_client.send.call_args_list
            if c.args[0] == "task_progress"
        ]
        # Chaque ligne espacee de 6s > 5s throttle, donc chacune envoyee + flush final
        assert len(progress_calls) >= 3


class TestProgressPayloadSchema:
    """Verifie que le payload task_progress respecte le schema attendu."""

    @pytest.mark.asyncio
    async def test_payload_matches_schema(self) -> None:
        """task_progress contient task_uuid (str), progress (int), output_lines (list[str])."""
        ws_client = AsyncMock()
        ws_client.send = AsyncMock()

        runner = TaskRunner(ws_client, allowed_tools=["nmap"])

        await runner._send_progress("uuid-abc", 42, ["Starting Nmap 7.94"])

        ws_client.send.assert_called_once()
        msg_type = ws_client.send.call_args.args[0]
        payload = ws_client.send.call_args.args[1]

        assert msg_type == "task_progress"
        assert isinstance(payload, dict)
        assert payload["task_uuid"] == "uuid-abc"
        assert isinstance(payload["progress"], int)
        assert payload["progress"] == 42
        assert isinstance(payload["output_lines"], list)
        assert all(isinstance(x, str) for x in payload["output_lines"])


# ── Tests filtrage credentials ──────────────────────────────────────


class TestCredentialFiltering:
    """Verifie que les lignes contenant des credentials sont filtrees."""

    @pytest.mark.parametrize("line,should_filter", [
        ("SMB password=Admin123", True),
        ("snmp secret=community", True),
        ("auth token=eyJhbGciOi...", True),
        ("login pwd=hunter2", True),
        ("PASSWORD= letmein", True),
        ("Discovered open port 22/tcp", False),
        ("Starting Nmap 7.94", False),
        ("Host is up (0.001s latency)", False),
        ("the password policy requires 8 chars", False),  # pas de "password="
    ])
    def test_credential_pattern(self, line: str, should_filter: bool) -> None:
        match = _CREDENTIAL_PATTERN.search(line) is not None
        assert match == should_filter, f"Line: {line!r}"

    @pytest.mark.asyncio
    async def test_send_progress_filters_credentials(self) -> None:
        """_send_progress remplace les lignes avec credentials par un placeholder."""
        ws_client = AsyncMock()
        ws_client.send = AsyncMock()

        runner = TaskRunner(ws_client, allowed_tools=["nmap"])

        await runner._send_progress("uuid-1", 50, [
            "Starting Nmap 7.94",
            "SMB password=Admin123",
            "Discovered open port 22/tcp",
            "auth token=eyJhbGciOi...",
        ])

        ws_client.send.assert_called_once()
        call_data = ws_client.send.call_args.args[1]
        lines = call_data["output_lines"]

        assert lines[0] == "Starting Nmap 7.94"
        assert lines[1] == "[FILTERED — credential detected]"
        assert lines[2] == "Discovered open port 22/tcp"
        assert lines[3] == "[FILTERED — credential detected]"

    @pytest.mark.asyncio
    async def test_credentials_filtered_in_full_flow(self) -> None:
        """Test end-to-end : outil -> task_runner -> WS avec filtrage."""
        ws_client = AsyncMock()
        ws_client.send = AsyncMock()

        runner = TaskRunner(ws_client, allowed_tools=["nmap"])
        tool = _FakeTool([
            "Starting scan",
            "Found creds: password=secret123",
            "Scan complete",
        ])
        runner.register_tool(tool)

        await runner.handle_new_task("new_task", {
            "task_uuid": "uuid-3",
            "tool": "nmap",
            "parameters": {"target": "10.0.0.1"},
        })

        assert runner._execution_task is not None
        await runner._execution_task

        # Trouver les appels task_progress
        progress_calls = [
            c for c in ws_client.send.call_args_list
            if c.args[0] == "task_progress"
        ]

        # Collecter toutes les lignes envoyees
        all_lines = []
        for call in progress_calls:
            all_lines.extend(call.args[1]["output_lines"])

        # La ligne avec password= doit etre filtree
        assert any("[FILTERED" in line for line in all_lines)
        assert not any("secret123" in line for line in all_lines)
