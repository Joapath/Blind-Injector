"""Build the application object graph from immutable configuration data."""

from core import (
    BinarySearchStrategy,
    BlindAttackEngine,
    BlindExtractor,
    BruteForceStrategy,
)
from detection import ErrorDetector, LengthDetector, StatusCodeDetector, TextDetector
from models import AttackConfiguration, RequestData
from payloads import (
    AsciiSubstringConditionBuilder,
    BodyParameterInjectionPoint,
    BooleanPayloadBuilder,
    ConditionalErrorPayloadBuilder,
    CookieInjectionPoint,
    OracleAsciiSubstringConditionBuilder,
    QueryParameterInjectionPoint,
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
    )
    if configuration.injection_location == "query":
        injection_point = QueryParameterInjectionPoint(configuration.parameter)
    elif configuration.injection_location == "body":
        injection_point = BodyParameterInjectionPoint(configuration.parameter)
    else:
        injection_point = CookieInjectionPoint(configuration.parameter)

    error_mode = configuration.attack_mode == "conditional-error" or configuration.detector == "error"
    if error_mode:
        detector = ErrorDetector(
            error_text=configuration.error_text or configuration.detector_value or None,
            error_regex=configuration.error_regex,
            error_status=configuration.error_status,
        )
    elif configuration.detector == "text":
        detector = TextDetector(configuration.detector_value)
    elif configuration.detector == "length":
        detector = LengthDetector(configuration.expected_length)  # type: ignore[arg-type]
    else:
        detector = StatusCodeDetector(configuration.expected_status)  # type: ignore[arg-type]

    payload_builder = (
        ConditionalErrorPayloadBuilder.for_oracle(
            table=configuration.table,
            user_column=configuration.user_column,
            username=configuration.username,
        )
        if error_mode
        else BooleanPayloadBuilder()
    )

    condition_builder = (
        OracleAsciiSubstringConditionBuilder()
        if error_mode
        else AsciiSubstringConditionBuilder()
    )

    strategy = (
        BruteForceStrategy()
        if configuration.strategy == "brute"
        else (
            BinarySearchStrategy("<=")
            if error_mode
            else BinarySearchStrategy()
        )
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
    return BlindAttackEngine(extractor)