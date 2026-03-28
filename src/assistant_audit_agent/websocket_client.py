"""Client WebSocket persistant avec reconnexion automatique.

Se connecte au serveur AssistantAudit via wss://{host}/ws/agent?token={jwt}
avec mTLS (certificat client). Reconnexion automatique avec backoff exponentiel
et jitter ±20% pour éviter le thundering herd.

Protocole (format JSON) :
    Agent → Serveur : {"type": "heartbeat"|"task_status"|"task_result", "data": {...}}
    Serveur → Agent : {"type": "heartbeat_ack"|"new_task", "data": {...}, "timestamp": "..."}
"""

from __future__ import annotations

import asyncio
import json
import logging
import random
import ssl
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Callable, Coroutine
from urllib.parse import urlparse

import websockets
from websockets.asyncio.client import ClientConnection

from assistant_audit_agent.config import AgentConfig

logger = logging.getLogger("websocket")

# Type pour les callbacks de messages
MessageHandler = Callable[[str, dict], Coroutine[Any, Any, None]]


class AgentWebSocketClient:
    """Client WebSocket persistant pour l'agent.

    Gère la connexion, la reconnexion automatique avec backoff exponentiel,
    et le dispatch des messages reçus du serveur.
    """

    def __init__(self, config: AgentConfig) -> None:
        self._config = config
        self._connection: ClientConnection | None = None
        self._running = False
        self._connected = False
        self._reconnect_attempt = 0

        # Callbacks (listes pour supporter plusieurs modules)
        self._on_connected_callbacks: list[Callable[[], Coroutine[Any, Any, None]]] = []
        self._on_disconnected_callbacks: list[Callable[[], Coroutine[Any, Any, None]]] = []
        self._message_handlers: dict[str, MessageHandler] = {}

    # ── Propriétés ────────────────────────────────────────────────────

    @property
    def is_connected(self) -> bool:
        """True si la connexion WebSocket est active."""
        return self._connected

    # ── Configuration des callbacks ───────────────────────────────────

    def on_connected(self, callback: Callable[[], Coroutine[Any, Any, None]]) -> None:
        """Enregistre un callback appelé à chaque connexion réussie."""
        self._on_connected_callbacks.append(callback)

    def on_disconnected(self, callback: Callable[[], Coroutine[Any, Any, None]]) -> None:
        """Enregistre un callback appelé à chaque déconnexion."""
        self._on_disconnected_callbacks.append(callback)

    def on_message(self, msg_type: str, handler: MessageHandler) -> None:
        """Enregistre un handler pour un type de message donné.

        Args:
            msg_type: Type de message (ex: "new_task", "heartbeat_ack").
            handler: Coroutine(msg_type, data) appelée à la réception.
        """
        self._message_handlers[msg_type] = handler

    # ── Cycle de vie ──────────────────────────────────────────────────

    async def start(self) -> None:
        """Boucle principale : connect → listen → reconnect.

        Ne retourne que quand stop() est appelé.
        """
        self._running = True
        logger.info("Démarrage du client WebSocket pour %s", self._config.agent_uuid)

        while self._running:
            try:
                await self._connect_and_listen()
            except asyncio.CancelledError:
                break
            except Exception as exc:
                logger.error("Erreur WebSocket : %s", exc)

            if not self._running:
                break

            await self._handle_disconnect()
            delay = self._compute_backoff_delay()
            self._reconnect_attempt += 1
            logger.info(
                "Reconnexion dans %.1fs... (tentative %d)",
                delay,
                self._reconnect_attempt,
            )
            await asyncio.sleep(delay)

        logger.info("Client WebSocket arrêté.")

    async def stop(self) -> None:
        """Arrête proprement le client WebSocket."""
        self._running = False
        if self._connection is not None:
            try:
                await self._connection.close()
            except Exception:
                pass
            self._connection = None
        await self._set_disconnected()

    async def force_reconnect(self) -> None:
        """Force la fermeture de la connexion pour déclencher une reconnexion."""
        logger.warning("Reconnexion forcée demandée.")
        if self._connection is not None:
            try:
                await self._connection.close()
            except Exception:
                pass

    # ── Envoi de messages ─────────────────────────────────────────────

    async def send(self, event_type: str, data: dict | None = None) -> None:
        """Envoie un message JSON au serveur.

        Format : {"type": event_type, "data": {...}}
        """
        if self._connection is None or not self._connected:
            logger.warning("Envoi impossible — non connecté.")
            return

        message = {
            "type": event_type,
            "data": data or {},
        }

        try:
            await self._connection.send(json.dumps(message))
        except Exception as exc:
            logger.error("Erreur d'envoi : %s", exc)

    # ── Connexion et écoute ───────────────────────────────────────────

    async def _connect_and_listen(self) -> None:
        """Établit la connexion et écoute les messages."""
        uri = self._build_ws_uri()
        ssl_context = self._build_ssl_context()

        logger.info("Connexion à %s...", uri.split("?")[0])

        self._connection = await websockets.connect(
            uri,
            ssl=ssl_context,
            close_timeout=5,
        )

        await self._set_connected()
        self._reconnect_attempt = 0

        try:
            async for raw_message in self._connection:
                await self._handle_message(raw_message)
        except websockets.ConnectionClosed as exc:
            logger.warning("Connexion fermée : code=%s reason=%s", exc.code, exc.reason)

    async def _handle_message(self, raw: str | bytes) -> None:
        """Parse et dispatch un message JSON reçu du serveur."""
        try:
            message = json.loads(raw)
        except (json.JSONDecodeError, TypeError):
            logger.warning("Message non-JSON reçu, ignoré.")
            return

        msg_type = message.get("type", "")
        data = message.get("data", {})

        handler = self._message_handlers.get(msg_type)
        if handler is not None:
            try:
                await handler(msg_type, data)
            except Exception:
                logger.exception("Erreur dans le handler pour '%s'", msg_type)
        else:
            logger.warning("Message inconnu : %s", msg_type)

    # ── Construction URL et SSL ───────────────────────────────────────

    def _build_ws_uri(self) -> str:
        """Construit l'URI WebSocket à partir de la config.

        https://server:8000 → wss://server:8000/ws/agent?token=xxx
        http://server:8000  → ws://server:8000/ws/agent?token=xxx
        """
        parsed = urlparse(self._config.server_url)
        scheme = "wss" if parsed.scheme == "https" else "ws"
        host = parsed.netloc or parsed.hostname or ""
        return f"{scheme}://{host}/ws/agent?token={self._config.jwt_token}"

    def _build_ssl_context(self) -> ssl.SSLContext | None:
        """Construit le contexte SSL/TLS avec certificat client (mTLS)."""
        parsed = urlparse(self._config.server_url)
        if parsed.scheme != "https":
            return None

        ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
        cert_paths = self._config.cert_paths
        ca_path = Path(cert_paths.ca)

        if ca_path.exists():
            ctx.load_verify_locations(str(ca_path))
        else:
            logger.warning(
                "CA cert (%s) introuvable — vérification serveur désactivée (dev only).",
                cert_paths.ca,
            )
            ctx.check_hostname = False
            ctx.verify_mode = ssl.CERT_NONE

        cert_file = Path(cert_paths.cert)
        key_file = Path(cert_paths.key)
        if cert_file.exists() and key_file.exists():
            ctx.load_cert_chain(str(cert_file), str(key_file))

        return ctx

    # ── Backoff exponentiel ───────────────────────────────────────────

    def _compute_backoff_delay(self) -> float:
        """Calcule le délai de reconnexion avec backoff exponentiel + jitter ±20%.

        Séquence de base : 1, 2, 4, 8, 16, 32, 60, 60, ...
        """
        base = self._config.reconnect_base_delay
        max_delay = self._config.reconnect_max_delay
        delay = min(base * (2 ** self._reconnect_attempt), max_delay)
        jitter = delay * 0.2 * (2 * random.random() - 1)  # ±20%
        return max(0.1, delay + jitter)

    # ── État interne ──────────────────────────────────────────────────

    async def _set_connected(self) -> None:
        self._connected = True
        logger.info("Connecté au serveur.")
        for callback in self._on_connected_callbacks:
            try:
                await callback()
            except Exception:
                logger.exception("Erreur dans on_connected callback")

    async def _set_disconnected(self) -> None:
        if not self._connected:
            return
        self._connected = False
        logger.info("Déconnecté du serveur.")
        for callback in self._on_disconnected_callbacks:
            try:
                await callback()
            except Exception:
                logger.exception("Erreur dans on_disconnected callback")

    async def _handle_disconnect(self) -> None:
        """Gère la déconnexion et déclenche le callback."""
        self._connection = None
        await self._set_disconnected()
