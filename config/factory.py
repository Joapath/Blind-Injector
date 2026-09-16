"""Build the application object graph from immutable configuration data."""

from core import (
    BinarySearchStrategy,
    BlindAttackEngine,
    BlindExtractor,
    BooleanTechnique,
    BruteForceStrategy,
    TimeBasedTechnique,
)
from detection import (
    ErrorDetector,
    LengthDetector,
    StatusCodeDetector,
    TextDetector,
    TimingDetector,
)
from models import AttackConfiguration, RequestData, TimingConfig
from payloads import (
    AsciiSubstringConditionBuilder,
    BodyParameterInjectionPoint,
    BooleanPayloadBuilder,
    ConditionalErrorPayloadBuilder,
    CookieInjectionPoint,
    OracleAsciiSubstringConditionBuilder,
    QueryParameterInjectionPoint,
    TimePayloadBuilder,
)
from transport import RequestsHttpClient


def build_attack_engine(configuration: AttackConfiguration) -> BlindAttackEngine:
    """Create the complete production object graph from configuration."""
    target = configuration.target
    request = RequestData(
        url=target.url,
        method=target.method,
        headers=target.headers,
        cookies=target.cookies,
        query=target.query,
        body=target.body,
    )
    http_client = RequestsHttpClient(
        timeout=configuration.timeout,
        verify_ssl=configuration.verify_ssl,
        proxy=configuration.proxy,
        allow_redirects=configuration.allow_redirects,
        max_retries=configuration.max_retries,
        retry_backoff=configuration.retry_backoff,
    )
    if configuration.injection_location == "query":
        injection_point = QueryParameterInjectionPoint(configuration.parameter)
    elif configuration.injection_location == "body":
        injection_point = BodyParameterInjectionPoint(configuration.parameter)
    else:
        injection_point = CookieInjectionPoint(configuration.parameter)

    error_mode = configuration.attack_mode == "conditional-error"
    if configuration.technique == "time":
        sleep_seconds = configuration.sleep_seconds
        timing_threshold = configuration.timing_threshold
        if sleep_seconds is None or timing_threshold is None:
            raise ValueError("time-based techniques require sleep_seconds and timing_threshold")
        timing = TimingConfig(
            sleep_seconds=sleep_seconds,
            threshold_seconds=timing_threshold,
            baseline_seconds=configuration.timing_baseline,
            tolerance_seconds=configuration.timing_tolerance,
        )
        detector = TimingDetector(
            threshold_seconds=timing.threshold_seconds,
            baseline_seconds=timing.baseline_seconds,
            tolerance_seconds=timing.tolerance_seconds,
        )
        payload_builder = TimePayloadBuilder(sleep_seconds=timing.sleep_seconds)
        condition_builder = AsciiSubstringConditionBuilder()
        strategy = (
            BruteForceStrategy()
            if configuration.strategy == "brute"
            else BinarySearchStrategy("<=")
        )
    elif error_mode:
        detector = ErrorDetector(
            error_text=configuration.error_text or configuration.detector_value or None,
            error_regex=configuration.error_regex,
            error_status=configuration.error_status,
        )
        payload_builder = ConditionalErrorPayloadBuilder.for_oracle(
            table=configuration.table,
            user_column=configuration.user_column,
            username=configuration.username,
        )
        condition_builder = OracleAsciiSubstringConditionBuilder()
        strategy = (
            BruteForceStrategy()
            if configuration.strategy == "brute"
            else BinarySearchStrategy("<=")
        )
    elif configuration.detector == "text":
        detector = TextDetector(configuration.detector_value)
        payload_builder = BooleanPayloadBuilder()
        condition_builder = AsciiSubstringConditionBuilder()
        strategy = (
            BruteForceStrategy()
            if configuration.strategy == "brute"
            else BinarySearchStrategy()
        )
    elif configuration.detector == "length":
        detector = LengthDetector(configuration.expected_length)  # type: ignore[arg-type]
        payload_builder = BooleanPayloadBuilder()
        condition_builder = AsciiSubstringConditionBuilder()
        strategy = (
            BruteForceStrategy()
            if configuration.strategy == "brute"
            else BinarySearchStrategy()
        )
    else:
        detector = StatusCodeDetector(configuration.expected_status)  # type: ignore[arg-type]
        payload_builder = BooleanPayloadBuilder()
        condition_builder = AsciiSubstringConditionBuilder()
        strategy = (
            BruteForceStrategy()
            if configuration.strategy == "brute"
            else BinarySearchStrategy()
        )

    extractor = BlindExtractor(
        http_client=http_client,
        condition_builder=condition_builder,
        payload_builder=payload_builder,
        injection_point=injection_point,
        detector=detector,
        search_strategy=strategy,
        base_request=request,
        charset=configuration.charset,
        max_length=configuration.max_length,
        delay=configuration.delay,
    )
    if configuration.technique == "time":
        technique = TimeBasedTechnique(extractor, timing)
    else:
        technique = BooleanTechnique(extractor)
    return BlindAttackEngine(technique)