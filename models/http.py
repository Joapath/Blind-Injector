"""HTTP-independent request and response models."""

from dataclasses import dataclass, field
from types import MappingProxyType
from typing import Mapping


@dataclass(frozen=True, slots=True)
class RequestData:
    """A fully described HTTP request, independent of an HTTP library."""

    url: str
    method: str = "GET"
    headers: Mapping[str, str] = field(default_factory=dict)
    cookies: Mapping[str, str] = field(default_factory=dict)
    query: Mapping[str, str] = field(default_factory=dict)
    body: Mapping[str, str] = field(default_factory=dict)

    def __post_init__(self) -> None:
        method = self.method.upper()
        if method not in {"GET", "POST"}:
            raise ValueError(f"Unsupported HTTP method: {self.method}")
        object.__setattr__(self, "method", method)
        for name in ("headers", "cookies", "query", "body"):
            object.__setattr__(self, name, MappingProxyType(dict(getattr(self, name))))


@dataclass(frozen=True, slots=True)
class HttpResponseData:
    """Normalized response consumed by detectors."""

    status_code: int
    text: str
    headers: Mapping[str, str] = field(default_factory=dict)
    elapsed_seconds: float = 0.0

    def __post_init__(self) -> None:
        if self.status_code < 100 or self.status_code > 599:
            raise ValueError("status_code must be between 100 and 599")
        if self.elapsed_seconds < 0:
            raise ValueError("elapsed_seconds cannot be negative")
        object.__setattr__(self, "headers", MappingProxyType(dict(self.headers)))

    @property
    def content_length(self) -> int:
        """Return the length of the decoded response text."""
        return len(self.text)
