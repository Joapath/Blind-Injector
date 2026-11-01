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

    def to_dict(self) -> dict[str, object]:
        """Return a JSON-safe snapshot of this result."""
        return {
            "position": self.position,
            "character": self.character,
            "attempts": self.attempts,
        }

    @classmethod
    def from_dict(cls, data: Mapping[str, object]) -> "CharacterResult":
        """Rebuild a result from a snapshot produced by :meth:`to_dict`."""
        return cls(
            position=int(data["position"]),  # type: ignore[arg-type]
            character=data["character"],  # type: ignore[arg-type]
            attempts=int(data["attempts"]),  # type: ignore[arg-type]
        )


@dataclass(frozen=True, slots=True)
class ExtractionResult:
    """Result of extracting one SQL expression."""

    expression: str
    value: str
    characters: tuple[CharacterResult, ...] = ()
    complete: bool = True

    def to_dict(self) -> dict[str, object]:
        """Return a JSON-safe snapshot of this result."""
        return {
            "expression": self.expression,
            "value": self.value,
            "characters": [character.to_dict() for character in self.characters],
            "complete": self.complete,
        }

    @classmethod
    def from_dict(cls, data: Mapping[str, object]) -> "ExtractionResult":
        """Rebuild a result from a snapshot produced by :meth:`to_dict`."""
        characters = tuple(
            CharacterResult.from_dict(item) for item in data["characters"]  # type: ignore[union-attr]
        )
        return cls(
            expression=data["expression"],  # type: ignore[arg-type]
            value=data["value"],  # type: ignore[arg-type]
            characters=characters,
            complete=bool(data["complete"]),
        )


@dataclass(frozen=True, slots=True)
class AttackResult:
    """Grouped results returned by the high-level engine."""

    extractions: Mapping[str, ExtractionResult] = field(default_factory=dict)

    def __post_init__(self) -> None:
        object.__setattr__(self, "extractions", MappingProxyType(dict(self.extractions)))
