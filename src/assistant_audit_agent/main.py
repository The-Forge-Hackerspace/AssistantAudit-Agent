"""Point d'entrée CLI de l'agent — commandes Click."""

from __future__ import annotations

import logging
import sys
from pathlib import Path

import click

from assistant_audit_agent import __version__
from assistant_audit_agent.config import AgentConfig, DEFAULT_CONFIG_PATH
from assistant_audit_agent.logging_config import setup_logging

logger = logging.getLogger("main")


@click.group()
def cli() -> None:
    """AssistantAudit-Agent — Agent d'audit de sécurité IT."""
    setup_logging()


@cli.command()
@click.option("--server", required=True, help="URL du serveur AssistantAudit (ex: https://server:8000)")
@click.option("--code", required=True, help="Code d'enrollment fourni par le serveur")
@click.option("--name", default=None, help="Nom de l'agent (défaut : hostname)")
@click.option("--ca-cert", default=None, help="Chemin vers le CA cert pour vérifier le serveur")
def enroll(server: str, code: str, name: str | None, ca_cert: str | None) -> None:
    """Enrôle l'agent auprès du serveur AssistantAudit."""
    from assistant_audit_agent.enrollment import EnrollmentError, enroll as do_enroll

    if AgentConfig.is_enrolled():
        if not click.confirm("Cet agent est déjà enregistré. Ré-enrôler ?"):
            click.echo("Abandon.")
            return
        # Supprimer l'ancienne config pour permettre le ré-enrollment
        DEFAULT_CONFIG_PATH.unlink(missing_ok=True)

    click.echo(f"Enrollment auprès de {server}...")

    try:
        result = do_enroll(
            server_url=server,
            enrollment_code=code,
            agent_name=name,
            ca_cert_path=ca_cert,
        )
    except EnrollmentError as exc:
        click.echo(f"Erreur : {exc}", err=True)
        sys.exit(1)

    click.echo(f"Enrollment réussi. Agent '{result.agent_name}' enregistré ({result.agent_uuid}).")


@cli.command()
def start() -> None:
    """Démarre le daemon agent (connexion WebSocket + heartbeat)."""
    if not AgentConfig.is_enrolled():
        click.echo("Agent non enrôlé. Lancez d'abord : assistant-audit-agent enroll --server URL --code CODE")
        sys.exit(1)

    config = AgentConfig.load()
    logger.info("Démarrage de l'agent %s → %s", config.agent_name, config.server_url)
    # TODO: Lancer websocket_client.py (étape 3)
    click.echo("Daemon non encore implémenté (étape 3).")


@cli.command()
def status() -> None:
    """Affiche l'état actuel de l'agent."""
    if not AgentConfig.is_enrolled():
        click.echo("État : non enrôlé")
        return

    config = AgentConfig.load()
    click.echo(f"État : enrôlé")
    click.echo(f"Agent : {config.agent_name} ({config.agent_uuid})")
    click.echo(f"Serveur : {config.server_url}")
    click.echo(f"Outils autorisés : {', '.join(config.allowed_tools)}")

    # Fichiers en attente dans queue/
    queue_path = Path("queue")
    pending = list(queue_path.glob("*.json")) if queue_path.exists() else []
    click.echo(f"Résultats en attente : {len(pending)}")


@cli.command("install-service")
def install_service() -> None:
    """Installe l'agent comme service Windows (placeholder)."""
    # TODO: Implémenter avec pywin32 ou NSSM
    click.echo("Installation du service Windows non encore implémentée.")


@cli.command()
def version() -> None:
    """Affiche la version de l'agent."""
    click.echo(f"assistant-audit-agent v{__version__}")
