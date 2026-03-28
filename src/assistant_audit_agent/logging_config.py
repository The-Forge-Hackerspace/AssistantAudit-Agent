"""Configuration du logging structuré avec rotation des fichiers."""

import logging
import os
import sys
from logging.handlers import RotatingFileHandler
from pathlib import Path

LOG_FORMAT = "[%(asctime)s] [%(levelname)s] [%(name)s] %(message)s"
DATE_FORMAT = "%Y-%m-%d %H:%M:%S"

MAX_BYTES = 10 * 1024 * 1024  # 10 MB
BACKUP_COUNT = 5
DEFAULT_LOG_FILE = "assistant-audit-agent.log"


def setup_logging(
    level: str = "INFO",
    log_file: str | None = DEFAULT_LOG_FILE,
) -> None:
    """Configure le logging avec sortie console + fichier rotatif.

    Args:
        level: Niveau de log (DEBUG, INFO, WARNING, ERROR, CRITICAL).
               Peut être surchargé par la variable d'environnement LOG_LEVEL.
        log_file: Chemin du fichier de log. None = console uniquement.
    """
    effective_level = os.environ.get("LOG_LEVEL", level).upper()
    root_logger = logging.getLogger()
    root_logger.setLevel(effective_level)

    # Supprime les handlers existants pour éviter les doublons
    root_logger.handlers.clear()

    formatter = logging.Formatter(LOG_FORMAT, datefmt=DATE_FORMAT)

    # Handler console
    console_handler = logging.StreamHandler(sys.stdout)
    console_handler.setFormatter(formatter)
    root_logger.addHandler(console_handler)

    # Handler fichier avec rotation
    if log_file is not None:
        log_path = Path(log_file)
        log_path.parent.mkdir(parents=True, exist_ok=True)
        file_handler = RotatingFileHandler(
            log_path,
            maxBytes=MAX_BYTES,
            backupCount=BACKUP_COUNT,
            encoding="utf-8",
        )
        file_handler.setFormatter(formatter)
        root_logger.addHandler(file_handler)

    logging.getLogger("websockets").setLevel(logging.WARNING)
    logging.getLogger("httpx").setLevel(logging.WARNING)
