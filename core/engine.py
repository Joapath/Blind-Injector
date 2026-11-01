"""High-level attack orchestration."""

import logging
import time
from collections.abc import Callable, Mapping, Sequence
from concurrent.futures import ThreadPoolExecutor, as_completed

from models.attack import AttackResult, CharacterResult, ExtractionResult

from .contracts import AttackEngine, Extractor
from .technique import Technique


logger = logging.getLogger(__name__)


class BlindAttackEngine(AttackEngine):
    """Delegate each requested expression through the configured technique or extractor."""

    def __init__(
        self,
        extractor: Extractor | Technique,
        *,
        extractor_factory: Callable[[], Extractor | Technique] | None = None,
        max_workers: int = 1,
    ) -> None:
        if max_workers < 1:
            raise ValueError("max_workers must be positive")
        if max_workers > 1 and extractor_factory is None:
            raise ValueError("max_workers greater than 1 requires an extractor_factory")
        self._extractor = extractor
        self._extractor_factory = extractor_factory
        self._max_workers = max_workers

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

    def run(
        self,
        expressions: Sequence[str],
        *,
        resume: Mapping[str, tuple[CharacterResult, ...]] | None = None,
    ) -> AttackResult:
        """Extract each expression and return an immutable grouped result.

        With the default ``max_workers=1`` this runs exactly as before: one
        sequential loop over ``self._extractor``. With ``max_workers>1`` (and
        an ``extractor_factory`` supplied at construction), each expression
        is extracted on its *own* fresh ``extractor_factory()`` instance in a
        thread pool -- never on the shared, stateful primary instance -- so
        concurrent extractions never race over ``BlindExtractor``'s internal
        ``_last_request``/``_last_response``/``_request_count`` bookkeeping.

        ``resume`` optionally maps an expression to characters already
        resolved in a previous, interrupted run (see ``core.checkpoint``);
        expressions absent from it extract from scratch, exactly as before.
        """
        expressions = tuple(expressions)
        if len(set(expressions)) != len(expressions):
            raise ValueError("expressions cannot contain duplicates")
        resume = resume or {}

        if self._is_technique(self._extractor):
            if not self._extractor.validate():
                raise ValueError("technique validation failed")

            max_oracle_attempts = 3
            for attempt in range(max_oracle_attempts):
                if self._extractor.probe() and self._extractor.confirm():
                    break
                if attempt < max_oracle_attempts - 1:
                    backoff = 0.5 * (2 ** attempt)
                    logger.info(
                        "Oracle check failed (attempt %d/%d), retrying in %.1fs",
                        attempt + 1, max_oracle_attempts, backoff,
                    )
                    time.sleep(backoff)
            else:
                raise ValueError("technique confirmation failed")

            evidence = self._extractor.collect_evidence()
            if not getattr(evidence, "oracle_valid", False):
                raise ValueError("technique oracle is invalid or unstable")

        def _extract_one(worker: Extractor | Technique, expression: str) -> ExtractionResult:
            if not expression.strip():
                raise ValueError("expression cannot be empty")
            logger.info("Starting extraction task")
            resume_from = resume.get(expression)
            if resume_from:
                return worker.extract(expression, resume_from=resume_from)
            return worker.extract(expression)

        if self._max_workers <= 1 or len(expressions) <= 1:
            results = {}
            for expression in expressions:
                results[expression] = _extract_one(self._extractor, expression)
            return AttackResult(results)

        results = {}
        with ThreadPoolExecutor(max_workers=self._max_workers) as pool:
            pending = {
                pool.submit(_extract_one, self._extractor_factory(), expression): expression
                for expression in expressions
            }
            for future in as_completed(pending):
                results[pending[future]] = future.result()
        return AttackResult(results)
