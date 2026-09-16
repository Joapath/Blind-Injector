"""High-level attack orchestration."""

import logging
from collections.abc import Sequence

from models.attack import AttackResult

from .contracts import AttackEngine, Extractor
from .technique import Technique


logger = logging.getLogger(__name__)


class BlindAttackEngine(AttackEngine):
    """Delegate each requested expression through the configured technique or extractor."""

    def __init__(self, extractor: Extractor | Technique) -> None:
        self._extractor = extractor

    @staticmethod
    def _is_technique(obj: object) -> bool:
        return (
            hasattr(obj, "validate")
            and callable(getattr(obj, "validate"))
            and hasattr(obj, "probe")
            and callable(getattr(obj, "probe"))
            and hasattr(obj, "confirm")
            and callable(getattr(obj, "confirm"))
        )

    def run(self, expressions: Sequence[str]) -> AttackResult:
        """Extract each expression and return an immutable grouped result."""
        expressions = tuple(expressions)
        if len(set(expressions)) != len(expressions):
            raise ValueError("expressions cannot contain duplicates")

        if self._is_technique(self._extractor):
            if not self._extractor.validate():
                raise ValueError("technique validation failed")
            if not self._extractor.probe():
                raise ValueError("technique probe failed")
            if not self._extractor.confirm():
                raise ValueError("technique confirmation failed")

        results = {}
        for expression in expressions:
            if not expression.strip():
                raise ValueError("expression cannot be empty")
            logger.info("Starting extraction task")
            results[expression] = self._extractor.extract(expression)

        return AttackResult(results)