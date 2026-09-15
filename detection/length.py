"""Response-length detector."""

from dataclasses import dataclass

from models.http import HttpResponseData

from .contracts import Detector


@dataclass(frozen=True, slots=True)
class LengthDetector(Detector):
    """Classify a response by comparing decoded text length."""

    expected_length: int
    tolerance: int = 0

    def __post_init__(self) -> None:
        if self.expected_length < 0:
            raise ValueError("expected_length cannot be negative")
        if self.tolerance < 0:
            raise ValueError("tolerance cannot be negative")

    def is_true(self, response: HttpResponseData) -> bool:
        return abs(response.content_length - self.expected_length) <= self.tolerance