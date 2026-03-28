"""Modules d'outils d'audit (nmap, ORADAD, AD collectors).

Chaque outil hérite de ToolBase et implémente execute() + cancel().
"""

from __future__ import annotations

from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Callable, Coroutine

# Callback(progress_percent: int, output_lines: list[str]) → None
OnProgressCallback = Callable[[int, list[str]], Coroutine[Any, Any, None]]


@dataclass(frozen=True)
class ToolResult:
    """Résultat d'exécution d'un outil."""

    success: bool
    output: dict = field(default_factory=dict)
    artifacts: list[Path] = field(default_factory=list)
    error: str | None = None


class ToolBase(ABC):
    """Classe abstraite pour les outils d'audit."""

    @property
    @abstractmethod
    def name(self) -> str:
        """Nom de l'outil (ex: 'nmap', 'oradad')."""
        ...

    @property
    def default_timeout(self) -> int:
        """Timeout par défaut en secondes (surchargeable par outil)."""
        return 3600  # 1 heure

    @abstractmethod
    async def execute(
        self,
        task_id: str,
        parameters: dict,
        on_progress: OnProgressCallback | None = None,
    ) -> ToolResult:
        """Exécute l'outil et retourne le résultat.

        Args:
            task_id: UUID de la tâche.
            parameters: Paramètres de la tâche (cibles, options, etc.).
            on_progress: Callback pour les mises à jour de progression.
        """
        ...

    @abstractmethod
    async def cancel(self) -> None:
        """Annule l'exécution en cours (kill subprocess + nettoyage)."""
        ...
