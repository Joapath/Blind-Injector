"""Configuration for time-based response classification."""

from dataclasses import dataclass


@dataclass(frozen=True, slots=True)
class TimingConfig:
    """Timing values shared by a temporal payload and its detector.

    ``threshold_seconds`` is the additional latency required above the
    configured baseline. ``tolerance_seconds`` reduces the threshold slightly
    to account for measurement jitter.
    """

    sleep_seconds: float
    threshold_seconds: float
    baseline_seconds: float = 0.0
    tolerance_seconds: float = 0.0
    samples: int = 1

    def __post_init__(self) -> None:
        if self.sleep_seconds <= 0:
            raise ValueError("sleep_seconds must be greater than zero")
        if self.threshold_seconds <= 0:
            raise ValueError("threshold_seconds must be greater than zero")
        if self.baseline_seconds < 0:
            raise ValueError("baseline_seconds cannot be negative")
        if self.tolerance_seconds < 0:
            raise ValueError("tolerance_seconds cannot be negative")
        if self.samples < 1:
            raise ValueError("samples must be positive")
        if self.threshold_seconds > self.sleep_seconds:
            raise ValueError("threshold_seconds cannot exceed sleep_seconds")

    @property
    def effective_threshold_seconds(self) -> float:
        """Return the minimum total elapsed time classified as true."""
        return max(
            0.0,
            self.baseline_seconds + self.threshold_seconds - self.tolerance_seconds,
        )
