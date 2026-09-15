"""HTTP status-code detector."""

from dataclasses import dataclass

from models.http import HttpResponseData

from .contracts import Detector


@dataclass(frozen=True, slots=True)
class StatusCodeDetector(Detector):
    """Classify a response by its HTTP status code."""

    expected_status: int

    def __post_init__(self) -> None:
        if self.expected_status < 100 or self.expected_status > 599:
            raise ValueError("expected_status must be between 100 and 599")

    def is_true(self, response: HttpResponseData) -> bool:
        return response.status_code == self.expected_status