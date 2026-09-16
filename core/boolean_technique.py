"""Boolean-based blind SQL injection technique."""

from __future__ import annotations

from core.blind_technique import BlindTechnique
from core.extractor import BlindExtractor


class BooleanTechnique(BlindTechnique):
    """Run boolean-based checks through a configured ``BlindExtractor``.

    The extractor owns payload construction, request injection, transport,
    response detection, and character extraction. This class only supplies the
    canonical true/false SQL conditions used by the oracle checks.
    """

    def __init__(
        self,
        extractor: BlindExtractor,
        *,
        true_condition: str = "1=1",
        false_condition: str = "1=2",
    ) -> None:
        super().__init__(extractor)
        self._configured_true_condition = true_condition
        self._configured_false_condition = false_condition

    def _true_condition(self) -> str:
        return self._configured_true_condition

    def _false_condition(self) -> str:
        return self._configured_false_condition

    def validate(self) -> bool:
        """Validate the technique-specific oracle conditions."""
        return super().validate()
