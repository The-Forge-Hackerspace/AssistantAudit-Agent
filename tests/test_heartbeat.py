"""Tests pour le service de heartbeat périodique."""

from __future__ import annotations

import asyncio
from unittest.mock import AsyncMock

import pytest

from assistant_audit_agent.config import AgentConfig
from assistant_audit_agent.heartbeat import (
    MAX_MISSED_ACKS,
    HeartbeatService,
    _collect_metadata,
    setup_heartbeat,
)
from assistant_audit_agent.websocket_client import AgentWebSocketClient


# ── Fixtures ─────────────────────────────────────────────────────────


@pytest.fixture()
def config() -> AgentConfig:
    return AgentConfig(
        agent_uuid="test-uuid",
        server_url="https://server:8000",
        jwt_token="fake-jwt",
        agent_name="PC-Test",
        heartbeat_interval=1,
    )


@pytest.fixture()
def client(config: AgentConfig) -> AgentWebSocketClient:
    return AgentWebSocketClient(config)


@pytest.fixture()
def service(client: AgentWebSocketClient) -> HeartbeatService:
    return HeartbeatService(client, interval=1)


# ── Tests envoi périodique ───────────────────────────────────────────


class TestHeartbeatSend:
    """Vérifie l'envoi périodique des heartbeats."""

    @pytest.mark.asyncio
    async def test_sends_heartbeat_periodically(self, service: HeartbeatService, client: AgentWebSocketClient) -> None:
        """Le heartbeat doit être envoyé à intervalle régulier."""
        client.send = AsyncMock()

        await service.start()
        await asyncio.sleep(0.15)  # Assez pour ~1 envoi (intervalle=1s mais on vérifie le premier)
        service.stop_sync()

        # Au moins 1 envoi
        assert client.send.await_count >= 1
        call_args = client.send.call_args
        assert call_args[0][0] == "heartbeat"

    @pytest.mark.asyncio
    async def test_heartbeat_data_contains_metadata(self, service: HeartbeatService, client: AgentWebSocketClient) -> None:
        """Le message heartbeat doit contenir les métadonnées de l'agent."""
        sent_data = {}

        async def capture_send(event_type: str, data: dict | None = None) -> None:
            sent_data.update(data or {})

        client.send = capture_send  # type: ignore[assignment]

        await service.start()
        await asyncio.sleep(0.1)
        service.stop_sync()

        assert "agent_version" in sent_data
        assert "os_info" in sent_data
        assert "hostname" in sent_data
        assert "local_ip" in sent_data
        assert "uptime_seconds" in sent_data
        assert "current_task" in sent_data

    @pytest.mark.asyncio
    async def test_current_task_included(self, service: HeartbeatService, client: AgentWebSocketClient) -> None:
        sent_data = {}

        async def capture_send(event_type: str, data: dict | None = None) -> None:
            sent_data.update(data or {})

        client.send = capture_send  # type: ignore[assignment]
        service.set_current_task("task-abc-123")

        await service.start()
        await asyncio.sleep(0.1)
        service.stop_sync()

        assert sent_data.get("current_task") == "task-abc-123"


# ── Tests start/stop ─────────────────────────────────────────────────


class TestHeartbeatLifecycle:
    """Tests du cycle de vie start/stop."""

    @pytest.mark.asyncio
    async def test_start_sets_running(self, service: HeartbeatService, client: AgentWebSocketClient) -> None:
        client.send = AsyncMock()

        await service.start()
        assert service.is_running is True

        service.stop_sync()
        await asyncio.sleep(0.05)
        assert service.is_running is False

    @pytest.mark.asyncio
    async def test_stop_cancels_task(self, service: HeartbeatService, client: AgentWebSocketClient) -> None:
        client.send = AsyncMock()

        await service.start()
        task = service._task
        assert task is not None
        await service.stop()

        # Attendre que la tâche finisse de s'annuler
        try:
            await asyncio.wait_for(task, timeout=0.5)
        except (asyncio.CancelledError, asyncio.TimeoutError):
            pass

        assert task.done()

    @pytest.mark.asyncio
    async def test_start_resets_pending_acks(self, service: HeartbeatService, client: AgentWebSocketClient) -> None:
        client.send = AsyncMock()
        service._pending_acks = 5

        await service.start()
        assert service._pending_acks == 0
        service.stop_sync()


# ── Tests intégration avec WebSocket client ──────────────────────────


class TestHeartbeatIntegration:
    """Tests de l'intégration heartbeat ↔ websocket client."""

    @pytest.mark.asyncio
    async def test_setup_heartbeat_starts_on_connect(self, client: AgentWebSocketClient) -> None:
        """Le heartbeat doit démarrer quand on_connected est appelé."""
        client.send = AsyncMock()
        hb = setup_heartbeat(client, interval=1)

        await client._set_connected()
        await asyncio.sleep(0.1)

        assert hb.is_running is True
        hb.stop_sync()
        # Reset pour _set_disconnected
        client._connected = True
        await client._set_disconnected()

    @pytest.mark.asyncio
    async def test_setup_heartbeat_stops_on_disconnect(self, client: AgentWebSocketClient) -> None:
        """Le heartbeat doit s'arrêter quand on_disconnected est appelé."""
        client.send = AsyncMock()
        hb = setup_heartbeat(client, interval=1)

        await client._set_connected()
        await asyncio.sleep(0.1)
        assert hb.is_running is True

        await client._set_disconnected()
        await asyncio.sleep(0.05)
        assert hb.is_running is False

    @pytest.mark.asyncio
    async def test_heartbeat_resumes_on_reconnect(self, client: AgentWebSocketClient) -> None:
        """Le heartbeat doit reprendre après reconnexion."""
        client.send = AsyncMock()
        hb = setup_heartbeat(client, interval=1)

        # Première connexion
        await client._set_connected()
        await asyncio.sleep(0.05)
        assert hb.is_running is True

        # Déconnexion
        await client._set_disconnected()
        await asyncio.sleep(0.05)
        assert hb.is_running is False

        # Reconnexion
        await client._set_connected()
        await asyncio.sleep(0.05)
        assert hb.is_running is True

        hb.stop_sync()
        client._connected = True
        await client._set_disconnected()


# ── Tests gestion des erreurs ────────────────────────────────────────


class TestHeartbeatErrors:
    """Tests de résilience aux erreurs."""

    @pytest.mark.asyncio
    async def test_send_failure_does_not_crash(self, service: HeartbeatService, client: AgentWebSocketClient) -> None:
        """Un échec d'envoi ne doit pas interrompre la boucle."""
        call_count = 0

        async def failing_send(event_type: str, data: dict | None = None) -> None:
            nonlocal call_count
            call_count += 1
            raise ConnectionError("broken pipe")

        client.send = failing_send  # type: ignore[assignment]

        await service.start()
        await asyncio.sleep(0.15)
        service.stop_sync()

        assert call_count >= 1

    @pytest.mark.asyncio
    async def test_missed_acks_forces_reconnect(self, service: HeartbeatService, client: AgentWebSocketClient) -> None:
        """3 heartbeats sans ack doivent forcer une reconnexion."""
        client.send = AsyncMock()
        client.force_reconnect = AsyncMock()

        # Simuler des envois sans ack
        service._pending_acks = MAX_MISSED_ACKS - 1

        await service._send_heartbeat()

        client.force_reconnect.assert_awaited_once()
        assert service._pending_acks == 0

    @pytest.mark.asyncio
    async def test_ack_resets_pending_counter(self, service: HeartbeatService, client: AgentWebSocketClient) -> None:
        """La réception d'un heartbeat_ack doit reset le compteur."""
        service._pending_acks = 2

        await service._handle_ack("heartbeat_ack", {})

        assert service._pending_acks == 0


# ── Tests métadonnées ────────────────────────────────────────────────


class TestCollectMetadata:
    """Tests de la collecte des métadonnées."""

    def test_metadata_fields(self) -> None:
        import time
        data = _collect_metadata(time.monotonic() - 100, "task-42")
        assert data["agent_version"] == "0.1.0"
        assert isinstance(data["os_info"], str)
        assert isinstance(data["hostname"], str)
        assert isinstance(data["local_ip"], str)
        assert data["uptime_seconds"] >= 99
        assert data["current_task"] == "task-42"

    def test_metadata_no_task(self) -> None:
        import time
        data = _collect_metadata(time.monotonic(), None)
        assert data["current_task"] is None
