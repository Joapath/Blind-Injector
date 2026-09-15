"""Contracts for SQL conditions, payloads, and injection points."""

from abc import ABC, abstractmethod

from models.http import RequestData


class ConditionBuilder(ABC):
    """Build one SQL condition without transport concerns."""

    @abstractmethod
    def build(self, expression: str, position: int, operator: str, value: int) -> str:
        """Return a SQL condition for one character position."""
        raise NotImplementedError


class PayloadBuilder(ABC):
    """Wrap a condition in the syntax required by a boolean payload."""

    @abstractmethod
    def build(self, condition: str) -> str:
        """Return a payload string without choosing its injection location."""
        raise NotImplementedError


class InjectionPoint(ABC):
    """Insert a payload into a request without mutating the original."""

    @abstractmethod
    def inject(self, request: RequestData, payload: str) -> RequestData:
        """Return a new request containing the payload."""
        raise NotImplementedError
