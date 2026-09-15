"""Core orchestration contracts."""

from abc import ABC, abstractmethod
from collections.abc import Callable, Sequence

from models.attack import AttackResult, CharacterResult, ExtractionResult


ConditionPredicate = Callable[[int], bool]


class SearchStrategy(ABC):
    """Find one character using only a boolean condition predicate."""

    @property
    @abstractmethod
    def comparison_operator(self) -> str:
        """Return the SQL comparison required by this strategy."""
        raise NotImplementedError

    @abstractmethod
    def find(
        self,
        position: int,
        charset: str,
        predicate: ConditionPredicate,
    ) -> CharacterResult:
        """Return the character found at position, or a failed result."""
        raise NotImplementedError


class Extractor(ABC):
    """Resolve one SQL expression into a string."""

    @abstractmethod
    def extract(self, expression: str) -> ExtractionResult:
        """Extract the value represented by expression."""
        raise NotImplementedError


class AttackEngine(ABC):
    """Coordinate extraction of one or more expressions."""

    @abstractmethod
    def run(self, expressions: Sequence[str]) -> AttackResult:
        """Run the configured extraction workflow."""
        raise NotImplementedError
