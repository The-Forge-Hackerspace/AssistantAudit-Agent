"""Heartbeat périodique envoyé au serveur via WebSocket.

Envoie un message {"type": "heartbeat", "data": {...}} toutes les N secondes.
Le serveur répond {"type": "heartbeat_ack", "data": {}}.
Si 3 heartbeats consécutifs restent sans réponse, force une reconnexion.
"""

from __future__ import annotations

import asyncio
import logging
import platform
import socket
import time

from assistant_audit_agent import __version__
from assistant_audit_agent.websocket_client import AgentWebSocketClient

logger = logging.getLogger("heartbeat")

MAX_MISSED_ACKS = 3


class HeartbeatService:
    """Service de heartbeat périodique.

    Démarre/arrête automatiquement via les callbacks on_connected/on_disconnected
    du client WebSocket.
    """

    def __init__(self, client: AgentWebSocketClient, interval: int = 30) -> None:
        self._client = client
        self._interval = interval
        self._task: asyncio.Task | None = None
        self._pending_acks = 0
        self._start_time = time.monotonic()
        self._current_task_id: str | None = None

        # Enregistrer le handler pour heartbeat_ack
        self._client.on_message("heartbeat_ack", self._handle_ack)

    # ── API publique ──────────────────────────────────────────────────

    async def start(self) -> None:
        """Démarre l'envoi périodique de heartbeats."""
        self.stop_sync()
        self._pending_acks = 0
        self._task = asyncio.create_task(self._loop())
        logger.info("Heartbeat démarré (intervalle=%ds)", self._interval)

    def stop_sync(self) -> None:
        """Arrête l'envoi de heartbeats (synchrone, annule la tâche)."""
        if self._task is not None and not self._task.done():
            self._task.cancel()
            self._task = None

    async def stop(self) -> None:
        """Arrête l'envoi de heartbeats (async)."""
        self.stop_sync()
        logger.info("Heartbeat arrêté.")

    @property
    def is_running(self) -> bool:
        """True si la boucle de heartbeat est active."""
        return self._task is not None and not self._task.done()

    def set_current_task(self, task_id: str | None) -> None:
        """Met à jour l'identifiant de la tâche en cours (inclus dans le heartbeat)."""
        self._current_task_id = task_id

    # ── Boucle interne ────────────────────────────────────────────────

    async def _loop(self) -> None:
        """Boucle d'envoi périodique."""
        try:
            while True:
                await self._send_heartbeat()
                await asyncio.sleep(self._interval)
        except asyncio.CancelledError:
            return

    async def _send_heartbeat(self) -> None:
        """Envoie un heartbeat avec les métadonnées de l'agent."""
        data = _collect_metadata(self._start_time, self._current_task_id)

        try:
            await self._client.send("heartbeat", data)
            self._pending_acks += 1
        except Exception:
            logger.warning("Échec d'envoi du heartbeat.")
            self._pending_acks += 1

        # Vérifier les acks manquants
        if self._pending_acks >= MAX_MISSED_ACKS:
            logger.warning(
                "%d heartbeats sans réponse — reconnexion forcée.",
                self._pending_acks,
            )
            self._pending_acks = 0
            await self._client.force_reconnect()

    async def _handle_ack(self, msg_type: str, data: dict) -> None:
        """Callback appelé à la réception d'un heartbeat_ack du serveur."""
        self._pending_acks = 0


# ── Collecte des métadonnées ─────────────────────────────────────────


def _collect_metadata(start_time: float, current_task_id: str | None) -> dict:
    """Collecte les métadonnées de l'agent pour le heartbeat."""
    return {
        "agent_version": __version__,
        "os_info": platform.platform(),
        "hostname": socket.gethostname(),
        "local_ip": _get_local_ip(),
        "uptime_seconds": int(time.monotonic() - start_time),
        "current_task": current_task_id,
    }


def _get_local_ip() -> str:
    """Récupère l'IP locale de l'interface réseau principale."""
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as s:
            s.connect(("8.8.8.8", 80))
            return s.getsockname()[0]
    except OSError:
        return "127.0.0.1"


def setup_heartbeat(client: AgentWebSocketClient, interval: int = 30) -> HeartbeatService:
    """Crée le HeartbeatService et l'enregistre sur le client WebSocket.

    Le heartbeat démarre/s'arrête automatiquement avec la connexion.
    """
    service = HeartbeatService(client, interval)

    async def on_connected() -> None:
        await service.start()

    async def on_disconnected() -> None:
        await service.stop()

    client.on_connected(on_connected)
    client.on_disconnected(on_disconnected)

    return service
