"""Error-based response detector."""

from dataclasses import dataclass, field
import re
from re import Pattern

from models.http import HttpResponseData

from .contracts import Detector


@dataclass(frozen=True, slots=True)
class ErrorDetector(Detector):
    """Classify responses using one explicit error signal.

    Regex takes precedence over text, which takes precedence over status.
    ``error_text`` remains positional so the original ``ErrorDetector("...")``
    API continues to work.
    """

    error_text: str | None = None
    error_regex: str | None = None
    error_status: int | None = None
    _compiled_regex: Pattern[str] | None = field(default=None, init=False, repr=False, compare=False)

    def __post_init__(self) -> None:
        if not any((self.error_text, self.error_regex, self.error_status is not None)):
            raise ValueError("at least one error signal is required")
        if self.error_status is not None and not 100 <= self.error_status <= 599:
            raise ValueError("error_status must be between 100 and 599")
        if self.error_regex is not None:
            object.__setattr__(self, "_compiled_regex", re.compile(self.error_regex))

    def is_true(self, response: HttpResponseData) -> bool:
        if self._compiled_regex is not None:
            return self._compiled_regex.search(response.text) is not None
        if self.error_text is not None:
            return self.error_text in response.text
        return response.status_code == self.error_status
