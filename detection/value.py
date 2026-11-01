"""Extract values embedded in database error responses."""

from dataclasses import dataclass, field
import re
from re import Pattern

from models.http import HttpResponseData


@dataclass(frozen=True, slots=True)
class ErrorValueExtractor:
    """Capture one value from a verbose database error message.

    The pattern must contain a named ``value`` group.  A caller can therefore
    adapt the parser to the exact error format returned by an authorized target
    without changing the transport or technique layers.
    """

    pattern: str
    _compiled: Pattern[str] = field(init=False, repr=False, compare=False)

    def __post_init__(self) -> None:
        if not self.pattern.strip():
            raise ValueError("pattern cannot be empty")
        compiled = re.compile(self.pattern, re.DOTALL)
        if "value" not in compiled.groupindex:
            raise ValueError("pattern must define a named 'value' group")
        object.__setattr__(self, "_compiled", compiled)

    def extract(self, response: HttpResponseData) -> str | None:
        """Return the captured value, or ``None`` when no value is present."""
        match = self._compiled.search(response.text)
        return match.group("value") if match is not None else None

    def matches(self, response: HttpResponseData) -> bool:
        """Return whether the response contains a matching value."""
        return self._compiled.search(response.text) is not None
