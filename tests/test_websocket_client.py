"""Tests pour le client WebSocket avec reconnexion automatique."""

from __future__ import annotations

import asyncio
import json
import logging
from unittest.mock import AsyncMock, MagicMock, patch

import pytest

from assistant_audit_agent.config import AgentConfig, CertPaths
from assistant_audit_agent.websocket_client import AgentWebSocketClient


# ── Fixtures ─────────────────────────────────────────────────────────


@pytest.fixture()
def config() -> AgentConfig:
    return AgentConfig(
        agent_uuid="test-uuid-1234",
        server_url="https://server:8000",
        jwt_token="fake-jwt-token",
        agent_name="PC-Test",
        cert_paths=CertPaths(ca="certs/ca.pem", cert="certs/agent.pem", key="certs/agent.key"),
    )


@pytest.fixture()
def client(config: AgentConfig) -> AgentWebSocketClient:
    return AgentWebSocketClient(config)


# ── Tests construction URL ───────────────────────────────────────────


class TestBuildWsUri:
    """Vérifie la construction de l'URI WebSocket."""

    def test_https_to_wss(self, client: AgentWebSocketClient) -> None:
        uri = client._build_ws_uri()
        assert uri.startswith("wss://")
        assert "/ws/agent?token=fake-jwt-token" in uri

    def test_http_to_ws(self) -> None:
        config = AgentConfig(
            agent_uuid="uuid", server_url="http://localhost:8000",
            jwt_token="tok", agent_name="test",
        )
        c = AgentWebSocketClient(config)
        uri = c._build_ws_uri()
        assert uri.startswith("ws://")

    def test_preserves_host_and_port(self, client: AgentWebSocketClient) -> None:
        uri = client._build_ws_uri()
        assert "server:8000" in uri


# ── Tests backoff exponentiel ────────────────────────────────────────


class TestBackoffDelay:
    """Vérifie le backoff exponentiel avec jitter."""

    def test_initial_delay_around_1s(self, client: AgentWebSocketClient) -> None:
        client._reconnect_attempt = 0
        delays = [client._compute_backoff_delay() for _ in range(100)]
        assert all(0.7 <= d <= 1.3 for d in delays)  # 1.0 ± 20% + rounding

    def test_exponential_growth(self, client: AgentWebSocketClient) -> None:
        """Vérifie la séquence de base : 1, 2, 4, 8, 16, 32, 60, 60."""
        expected_bases = [1, 2, 4, 8, 16, 32, 60, 60]
        for attempt, expected_base in enumerate(expected_bases):
            client._reconnect_attempt = attempt
            delays = [client._compute_backoff_delay() for _ in range(50)]
            avg = sum(delays) / len(delays)
            # L'average doit être proche de la base (jitter s'annule statistiquement)
            assert abs(avg - expected_base) < expected_base * 0.4, (
                f"Tentative {attempt}: avg={avg:.2f}, attendu≈{expected_base}"
            )

    def test_max_delay_capped(self, client: AgentWebSocketClient) -> None:
        client._reconnect_attempt = 100
        delays = [client._compute_backoff_delay() for _ in range(50)]
        assert all(d <= 72.0 for d in delays)  # 60 + 20% max

    def test_jitter_adds_variation(self, client: AgentWebSocketClient) -> None:
        """Le délai ne doit jamais être exactement le double du précédent."""
        client._reconnect_attempt = 2  # base = 4s
        delays = set()
        for _ in range(20):
            delays.add(round(client._compute_backoff_delay(), 6))
        # Avec jitter, on doit avoir des valeurs différentes
        assert len(delays) > 1


# ── Tests connexion et déconnexion ───────────────────────────────────


class TestConnectionLifecycle:
    """Tests du cycle connect/disconnect/reconnect."""

    @pytest.mark.asyncio
    async def test_is_connected_initially_false(self, client: AgentWebSocketClient) -> None:
        assert client.is_connected is False

    @pytest.mark.asyncio
    async def test_on_connected_callback(self, client: AgentWebSocketClient) -> None:
        callback = AsyncMock()
        client.on_connected(callback)

        await client._set_connected()

        assert client.is_connected is True
        callback.assert_awaited_once()

    @pytest.mark.asyncio
    async def test_on_disconnected_callback(self, client: AgentWebSocketClient) -> None:
        callback = AsyncMock()
        client.on_disconnected(callback)

        # Doit être connecté d'abord pour déclencher on_disconnected
        await client._set_connected()
        await client._set_disconnected()

        assert client.is_connected is False
        callback.assert_awaited_once()

    @pytest.mark.asyncio
    async def test_on_disconnected_not_called_if_already_disconnected(
        self, client: AgentWebSocketClient
    ) -> None:
        callback = AsyncMock()
        client.on_disconnected(callback)

        await client._set_disconnected()
        callback.assert_not_awaited()

    @pytest.mark.asyncio
    async def test_reconnect_attempt_resets_on_connect(
        self, client: AgentWebSocketClient
    ) -> None:
        """Le compteur de reconnexion reset après connexion réussie."""
        client._reconnect_attempt = 5

        # Simule une connexion réussie via _connect_and_listen
        mock_ws = AsyncMock()
        mock_ws.__aiter__ = MagicMock(return_value=iter([]))
        mock_ws.close = AsyncMock()

        # websockets.connect() est un coroutine qui retourne la connexion
        async def fake_connect(*args, **kwargs):
            return mock_ws

        with patch("assistant_audit_agent.websocket_client.websockets.connect", side_effect=fake_connect):
            try:
                await client._connect_and_listen()
            except Exception:
                pass

        assert client._reconnect_attempt == 0

    @pytest.mark.asyncio
    async def test_stop_closes_connection(self, client: AgentWebSocketClient) -> None:
        mock_ws = AsyncMock()
        client._connection = mock_ws
        client._connected = True

        await client.stop()

        assert client._running is False
        mock_ws.close.assert_awaited_once()
        assert client.is_connected is False


# ── Tests dispatch de messages ───────────────────────────────────────


class TestMessageDispatch:
    """Tests de réception et dispatch des messages."""

    @pytest.mark.asyncio
    async def test_known_message_dispatched(self, client: AgentWebSocketClient) -> None:
        handler = AsyncMock()
        client.on_message("new_task", handler)

        raw = json.dumps({"type": "new_task", "data": {"task_uuid": "t1", "tool": "nmap"}})
        await client._handle_message(raw)

        handler.assert_awaited_once_with("new_task", {"task_uuid": "t1", "tool": "nmap"})

    @pytest.mark.asyncio
    async def test_heartbeat_ack_dispatched(self, client: AgentWebSocketClient) -> None:
        handler = AsyncMock()
        client.on_message("heartbeat_ack", handler)

        raw = json.dumps({"type": "heartbeat_ack", "data": {}})
        await client._handle_message(raw)

        handler.assert_awaited_once_with("heartbeat_ack", {})

    @pytest.mark.asyncio
    async def test_unknown_message_logs_warning(
        self, client: AgentWebSocketClient, caplog
    ) -> None:
        with caplog.at_level(logging.WARNING, logger="websocket"):
            raw = json.dumps({"type": "alien_signal", "data": {}})
            await client._handle_message(raw)

        assert "Message inconnu" in caplog.text
        assert "alien_signal" in caplog.text

    @pytest.mark.asyncio
    async def test_invalid_json_ignored(
        self, client: AgentWebSocketClient, caplog
    ) -> None:
        with caplog.at_level(logging.WARNING, logger="websocket"):
            await client._handle_message("not json{{{")

        assert "non-JSON" in caplog.text

    @pytest.mark.asyncio
    async def test_handler_exception_does_not_crash(
        self, client: AgentWebSocketClient, caplog
    ) -> None:
        async def bad_handler(msg_type: str, data: dict) -> None:
            raise ValueError("boom")

        client.on_message("new_task", bad_handler)

        with caplog.at_level(logging.ERROR, logger="websocket"):
            raw = json.dumps({"type": "new_task", "data": {}})
            await client._handle_message(raw)

        assert "Erreur dans le handler" in caplog.text


# ── Tests envoi de messages ──────────────────────────────────────────


class TestSendMessage:
    """Tests de l'envoi de messages au serveur."""

    @pytest.mark.asyncio
    async def test_send_formats_correctly(self, client: AgentWebSocketClient) -> None:
        mock_ws = AsyncMock()
        client._connection = mock_ws
        client._connected = True

        await client.send("heartbeat", {"version": "0.1.0"})

        sent_raw = mock_ws.send.call_args[0][0]
        sent = json.loads(sent_raw)
        assert sent["type"] == "heartbeat"
        assert sent["data"]["version"] == "0.1.0"

    @pytest.mark.asyncio
    async def test_send_when_disconnected_logs_warning(
        self, client: AgentWebSocketClient, caplog
    ) -> None:
        with caplog.at_level(logging.WARNING, logger="websocket"):
            await client.send("heartbeat")

        assert "non connecté" in caplog.text


# ── Tests SSL context ────────────────────────────────────────────────


class TestSSLContext:
    """Tests de la construction du contexte SSL."""

    def test_http_returns_none(self) -> None:
        config = AgentConfig(
            agent_uuid="uuid", server_url="http://localhost:8000",
            jwt_token="tok", agent_name="test",
        )
        c = AgentWebSocketClient(config)
        assert c._build_ssl_context() is None

    def test_https_without_ca_warns(self, client: AgentWebSocketClient, caplog, tmp_path, monkeypatch) -> None:
        """Sans ca.pem, le client doit logger un warning et désactiver la vérif."""
        monkeypatch.chdir(tmp_path)
        with caplog.at_level(logging.WARNING, logger="websocket"):
            ctx = client._build_ssl_context()
        assert ctx is not None
        assert "CA cert" in caplog.text


# ── Tests intégration start/stop ─────────────────────────────────────


class TestStartStop:
    """Tests du cycle start/stop."""

    @pytest.mark.asyncio
    async def test_start_stop_lifecycle(self, client: AgentWebSocketClient) -> None:
        """start() doit s'arrêter quand stop() est appelé."""
        connect_count = 0

        async def fake_connect(*args, **kwargs):
            nonlocal connect_count
            connect_count += 1
            raise ConnectionRefusedError("test")

        with patch(
            "assistant_audit_agent.websocket_client.websockets.connect",
            side_effect=fake_connect,
        ):
            # Lancer start() puis l'arrêter après un bref délai
            task = asyncio.create_task(client.start())
            await asyncio.sleep(0.3)
            await client.stop()

            # Attendre que start() se termine
            await asyncio.wait_for(task, timeout=2.0)

        assert not client.is_connected
        assert connect_count >= 1


# ── Tests CLI start ──────────────────────────────────────────────────


class TestStartCLI:
    """Tests de la commande CLI start."""

    def test_start_not_enrolled(self, tmp_path, monkeypatch) -> None:
        from click.testing import CliRunner
        from assistant_audit_agent.main import cli

        monkeypatch.chdir(tmp_path)
        runner = CliRunner()
        result = runner.invoke(cli, ["start"])
        assert result.exit_code != 0
        assert "non enrôlé" in result.output


# ── Helpers ──────────────────────────────────────────────────────────


def _async_context(mock_ws):
    """Crée un context manager async qui retourne mock_ws."""

    class _FakeAsyncCtx:
        async def __aenter__(self):
            return mock_ws

        async def __aexit__(self, *args):
            pass

    return _FakeAsyncCtx()
