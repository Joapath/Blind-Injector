"""High-level attack orchestration."""

import logging
from collections.abc import Sequence

from models.attack import AttackResult

from .contracts import AttackEngine, Extractor


logger = logging.getLogger(__name__)


class BlindAttackEngine(AttackEngine):
    """Delegate each requested expression to one configured extractor."""

    def __init__(self, extractor: Extractor) -> None:
        self._extractor = extractor

    def run(self, expressions: Sequence[str]) -> AttackResult:
        """Extract each expression and return an immutable grouped result."""
        expressions = tuple(expressions)
        if len(set(expressions)) != len(expressions):
            raise ValueError("expressions cannot contain duplicates")

        results = {}
        for expression in expressions:
            if not expression.strip():
                raise ValueError("expression cannot be empty")
            logger.info("Starting extraction task")
            results[expression] = self._extractor.extract(expression)

        return AttackResult(results)