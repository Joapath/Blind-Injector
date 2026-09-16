"""HTTP-independent character search strategies."""

from collections.abc import Callable
from dataclasses import dataclass

from models.attack import CharacterResult

from .contracts import ConditionPredicate, SearchStrategy


def _validate_inputs(position: int, charset: str, predicate: ConditionPredicate) -> None:
    if position < 1:
        raise ValueError("position must be positive")
    if not charset:
        raise ValueError("charset cannot be empty")
    if len(set(charset)) != len(charset):
        raise ValueError("charset cannot contain duplicate characters")
    if not callable(predicate):
        raise TypeError("predicate must be callable")


@dataclass(frozen=True, slots=True)
class BruteForceStrategy(SearchStrategy):
    """Try each candidate until the equality predicate succeeds."""

    @property
    def comparison_operator(self) -> str:
        return "="

    def find(
        self,
        position: int,
        charset: str,
        predicate: ConditionPredicate,
        confirmation: ConditionPredicate | None = None,
    ) -> CharacterResult:
        _validate_inputs(position, charset, predicate)
        attempts = 0
        for character in charset:
            attempts += 1
            if predicate(ord(character)):
                return CharacterResult(position, character, attempts)
        return CharacterResult(position, None, attempts)


@dataclass(frozen=True, slots=True)
class BinarySearchStrategy(SearchStrategy):
    """Find a character with a monotonic threshold predicate.

    The default comparison is ``>=``. Conditional-error payloads often use the inverse
    predicate ``<=`` instead, so the operator is configurable without changing the rest
    of the framework.
    """

    comparison_operator: str = ">="

    def __post_init__(self) -> None:
        if self.comparison_operator not in {">=", "<="}:
            raise ValueError("comparison_operator must be >= or <=")

    def find(
        self,
        position: int,
        charset: str,
        predicate: ConditionPredicate,
        confirmation: ConditionPredicate | None = None,
    ) -> CharacterResult:
        _validate_inputs(position, charset, predicate)
        values = sorted(ord(character) for character in charset)
        attempts = 0

        if self.comparison_operator == ">=":
            attempts += 1
            if not predicate(values[0]):
                return CharacterResult(position, None, attempts)

            low = 0
            high = len(values) - 1
            while low < high:
                middle = (low + high + 1) // 2
                attempts += 1
                if predicate(values[middle]):
                    low = middle
                else:
                    high = middle - 1

            candidate = chr(values[low])
            if confirmation is not None:
                attempts += 1
                if not confirmation(values[low]):
                    return CharacterResult(position, None, attempts)
            return CharacterResult(position, candidate, attempts)

        attempts += 1
        if not predicate(values[-1]):
            return CharacterResult(position, None, attempts)

        low = 0
        high = len(values) - 1
        while low < high:
            middle = (low + high) // 2
            attempts += 1
            if predicate(values[middle]):
                high = middle
            else:
                low = middle + 1

        candidate = chr(values[low])
        if confirmation is not None:
            attempts += 1
            if not confirmation(values[low]):
                return CharacterResult(position, None, attempts)
        return CharacterResult(position, candidate, attempts)