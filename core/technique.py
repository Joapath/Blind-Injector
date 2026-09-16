# core/technique.py

from __future__ import annotations
from abc import ABC, abstractmethod
from typing import Any

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
    def extract(self, expression: str) -> Any:
        """Extract the requested expression from the configured target."""
        ...

    @abstractmethod
    def collect_evidence(self) -> Evidence:
        """Devuelve la Evidence acumulada de este run, con confidence resuelto."""
        ...