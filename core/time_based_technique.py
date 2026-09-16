"""Time-based blind SQL injection technique."""

from __future__ import annotations

from core.blind_technique import BlindTechnique
from core.extractor import BlindExtractor
from models.timing import TimingConfig


class TimeBasedTechnique(BlindTechnique):
    """Use response latency as the boolean oracle signal.

    A ``TimingDetector`` and ``TimePayloadBuilder`` configured with the same
    timing values must be supplied to the wrapped ``BlindExtractor``.
    """

    def __init__(
        self,
        extractor: BlindExtractor,
        timing: TimingConfig,
        *,
        true_condition: str = "1=1",
        false_condition: str = "1=2",
    ) -> None:
        super().__init__(extractor)
        self._timing = timing
        self._configured_true_condition = true_condition
        self._configured_false_condition = false_condition

    def _true_condition(self) -> str:
        return self._configured_true_condition

    def _false_condition(self) -> str:
        return self._configured_false_condition

    def validate(self) -> bool:
        """Validate oracle conditions and temporal configuration."""
        return super().validate() and self._timing.threshold_seconds <= self._timing.sleep_seconds

    @property
    def timing(self) -> TimingConfig:
        """Return the immutable timing configuration."""
        return self._timing
