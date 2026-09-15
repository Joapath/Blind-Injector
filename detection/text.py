"""Text-based response detector."""

from dataclasses import dataclass

from models.http import HttpResponseData

from .contracts import Detector


@dataclass(frozen=True, slots=True)
class TextDetector(Detector):
    """Classify a response by checking whether it contains expected text."""

    expected_text: str
    case_sensitive: bool = True

    def __post_init__(self) -> None:
        if not self.expected_text:
            raise ValueError("expected_text cannot be empty")

    def is_true(self, response: HttpResponseData) -> bool:
        if self.case_sensitive:
            return self.expected_text in response.text
        return self.expected_text.casefold() in response.text.casefold()