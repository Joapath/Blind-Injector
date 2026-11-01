# core/technique.py

from __future__ import annotations
from abc import ABC, abstractmethod
from typing import Any

from models.attack import CharacterResult
from models.evidence import Evidence


class Technique(ABC):
    """Contrato común para una técnica configurada contra un target."""

    @abstractmethod
    def validate(self) -> bool:
        """Validate technique-specific configuration without network I/O."""
        ...

    @abstractmethod
    def probe(self) -> bool:
        """Run the first independent oracle check."""
        ...

    @abstractmethod
    def confirm(self) -> bool:
        """Run an independent confirmation check."""
        ...

    @abstractmethod
    def extract(
        self, expression: str, *, resume_from: tuple[CharacterResult, ...] = ()
    ) -> Any:
        """Extract the requested expression from the configured target.

        ``resume_from`` optionally seeds positions already resolved by a
        previous, interrupted run (see ``core.checkpoint``). Techniques that
        have no notion of partial, per-position progress may accept and
        ignore it.
        """
        ...

    @abstractmethod
    def collect_evidence(self) -> Evidence:
        """Devuelve la Evidence acumulada de este run, con confidence resuelto."""
        ...