"""Extraction result models."""

from dataclasses import dataclass, field
from types import MappingProxyType
from typing import Mapping


@dataclass(frozen=True, slots=True)
class CharacterResult:
    """Result for one character position."""

    position: int
    character: str | None
    attempts: int = 0

    def __post_init__(self) -> None:
        if self.position < 1:
            raise ValueError("position must be positive")
        if self.character is not None and len(self.character) != 1:
            raise ValueError("character must contain exactly one character")
        if self.attempts < 0:
            raise ValueError("attempts cannot be negative")


@dataclass(frozen=True, slots=True)
class ExtractionResult:
    """Result of extracting one SQL expression."""

    expression: str
    value: str
    characters: tuple[CharacterResult, ...] = ()
    complete: bool = True


@dataclass(frozen=True, slots=True)
class AttackResult:
    """Grouped results returned by the high-level engine."""

    extractions: Mapping[str, ExtractionResult] = field(default_factory=dict)

    def __post_init__(self) -> None:
        object.__setattr__(self, "extractions", MappingProxyType(dict(self.extractions)))
