"""Timing-based response detector."""

from dataclasses import dataclass

from models.http import HttpResponseData

from .contracts import Detector


@dataclass(frozen=True, slots=True)
class TimingDetector(Detector):
    """Classify a response as true when its latency crosses a threshold."""

    threshold_seconds: float
    baseline_seconds: float = 0.0
    tolerance_seconds: float = 0.0

    def __post_init__(self) -> None:
        if self.threshold_seconds <= 0:
            raise ValueError("threshold_seconds must be greater than zero")
        if self.baseline_seconds < 0:
            raise ValueError("baseline_seconds cannot be negative")
        if self.tolerance_seconds < 0:
            raise ValueError("tolerance_seconds cannot be negative")

    def is_true(self, response: HttpResponseData) -> bool:
        threshold = max(
            0.0,
            self.baseline_seconds
            + self.threshold_seconds
            - self.tolerance_seconds,
        )
        return response.elapsed_seconds >= threshold
