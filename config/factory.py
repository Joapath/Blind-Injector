"""Build the application object graph from immutable configuration data.

``build_attack_engine`` never performs network I/O: it only wires concrete
adapters together, same as before this module grew calibration/rate-limit/
parallelism/tamper/fingerprint support. Automatic timing calibration and
fingerprinting *do* perform real requests, so they are deliberately separate,
explicit functions (``calibrate_timing``, ``fingerprint``) that callers (the
CLI) invoke before composing the engine -- never silently from inside
composition.

Technique selection is a small registry (``_TECHNIQUE_BUILDERS``) keyed by
``configuration.technique``, each entry a function building one kind of
``Technique`` from a shared ``_BuildContext``. Adding a technique later means
adding one function and one registry entry -- never growing a single
if/elif chain.
"""

from collections.abc import Callable
from dataclasses import dataclass

from core import (
    BinarySearchStrategy,
    BlindAttackEngine,
    BlindExtractor,
    BooleanTechnique,
    BruteForceStrategy,
    FingerprintResult,
    RandomForwardedForMutator,
    RandomUserAgentMutator,
    RateLimiter,
    TechniqueFingerprinter,
    TimeBasedTechnique,
    TimingCalibrator,
    VisibleErrorTechnique,
)
from core.contracts import SearchStrategy
from core.technique import Technique
from detection import (
    Detector,
    ErrorDetector,
    ErrorValueExtractor,
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
    InjectionPoint,
    OracleAsciiSubstringConditionBuilder,
    PayloadBuilder,
    PostgresCastPayloadBuilder,
    QueryParameterInjectionPoint,
    TamperingPayloadBuilder,
    TimePayloadBuilder,
    build_tamper,
)
from transport import HeaderMutatingHttpClient, HttpClient, RateLimitedHttpClient, RequestsHttpClient


def _build_request(configuration: AttackConfiguration) -> RequestData:
    target = configuration.target
    return RequestData(
        url=target.url,
        method=target.method,
        headers=target.headers,
        cookies=target.cookies,
        query=target.query,
        body=target.body,
    )


def _build_http_client(configuration: AttackConfiguration) -> HttpClient:
    http_client: HttpClient = RequestsHttpClient(
        timeout=configuration.timeout,
        verify_ssl=configuration.verify_ssl,
        proxy=configuration.proxy,
        allow_redirects=configuration.allow_redirects,
        max_retries=configuration.max_retries,
        retry_backoff=configuration.retry_backoff,
    )
    mutators = []
    if configuration.random_agent:
        mutators.append(RandomUserAgentMutator())
    if configuration.random_forwarded_for:
        mutators.append(RandomForwardedForMutator())
    if mutators:
        http_client = HeaderMutatingHttpClient(http_client, tuple(mutators))
    if configuration.rate_limit is not None:
        # Outermost: the rate limit governs the real pace of requests no
        # matter what other decorator ran first.
        http_client = RateLimitedHttpClient(http_client, RateLimiter(configuration.rate_limit))
    return http_client


def _build_injection_point(configuration: AttackConfiguration) -> InjectionPoint:
    if configuration.injection_location == "query":
        return QueryParameterInjectionPoint(configuration.parameter, configuration.injection_mode)
    if configuration.injection_location == "body":
        return BodyParameterInjectionPoint(configuration.parameter, configuration.injection_mode)
    return CookieInjectionPoint(configuration.parameter, configuration.injection_mode)


def _apply_tampers(configuration: AttackConfiguration, payload_builder: PayloadBuilder) -> PayloadBuilder:
    if not configuration.tampers:
        return payload_builder
    tampers = tuple(build_tamper(name) for name in configuration.tampers)
    return TamperingPayloadBuilder(inner=payload_builder, tampers=tampers)


def _build_strategy(configuration: AttackConfiguration, operator: str = ">=") -> SearchStrategy:
    """Return the configured search strategy.

    ``operator`` is only meaningful for binary search; techniques whose
    oracle is a one-directional signal (time, Oracle conditional-error) use
    ``"<="`` because their comparison direction is inverted relative to the
    default boolean oracle's ``">="``.
    """
    if configuration.strategy == "brute":
        return BruteForceStrategy()
    return BinarySearchStrategy(operator)


def calibrate_timing(configuration: AttackConfiguration) -> tuple[float, float]:
    """Measure real latency and return ``(baseline_seconds, tolerance_seconds)``.

    This is the only place in ``config``/``core`` that performs network I/O
    outside of an actual attack run, together with :func:`fingerprint`. Call
    it explicitly -- e.g. from the CLI, as a visible pre-flight step -- and
    feed the result back into a new configuration's ``timing_baseline``/
    ``timing_tolerance`` (configurations are immutable) before calling
    :func:`build_attack_engine`.
    """
    if configuration.technique != "time":
        raise ValueError("timing calibration only applies to technique=time")
    if configuration.sleep_seconds is None:
        raise ValueError("time-based techniques require sleep_seconds")

    http_client = _build_http_client(configuration)
    injection_point = _build_injection_point(configuration)
    payload_builder = TimePayloadBuilder(sleep_seconds=configuration.sleep_seconds)
    calibrator = TimingCalibrator(
        http_client=http_client,
        injection_point=injection_point,
        payload_builder=payload_builder,
        base_request=_build_request(configuration),
        delay=configuration.delay,
    )
    mean, stdev = calibrator.calibrate(configuration.calibration_samples)
    tolerance = max(
        configuration.timing_tolerance,
        stdev * configuration.calibration_tolerance_factor,
    )
    return mean, tolerance


def fingerprint(configuration: AttackConfiguration) -> FingerprintResult:
    """Probe the configured injection point and recommend technique/detector.

    Like :func:`calibrate_timing`, this is explicit, visible network I/O
    performed outside of composition -- call it before
    :func:`build_attack_engine` (e.g. from the CLI when ``technique=="auto"``)
    and feed its result back into a new, fully-validated configuration via
    ``dataclasses.replace``. Never applied silently.
    """
    http_client = _build_http_client(configuration)
    injection_point = _build_injection_point(configuration)
    fingerprinter = TechniqueFingerprinter(
        http_client=http_client,
        injection_point=injection_point,
        base_request=_build_request(configuration),
        delay=configuration.delay,
    )
    return fingerprinter.run()


@dataclass(frozen=True, slots=True)
class _BuildContext:
    """Everything one technique builder needs, bundled so the registry's
    functions share a single-argument signature instead of five loose ones."""

    configuration: AttackConfiguration
    http_client: HttpClient
    injection_point: InjectionPoint
    request: RequestData
    on_progress: Callable[[str, tuple, bool], None] | None


# Boolean detector selection: all three shapes build the identical payload/
# condition/strategy and differ only in which Detector reads the response.
_BOOLEAN_DETECTOR_FACTORIES: dict[str, Callable[[AttackConfiguration], Detector]] = {
    "text": lambda c: TextDetector(c.detector_value),
    "length": lambda c: LengthDetector(c.expected_length),  # type: ignore[arg-type]
    "status": lambda c: StatusCodeDetector(c.expected_status),  # type: ignore[arg-type]
}


def _build_boolean_technique(ctx: _BuildContext) -> Technique:
    """Covers plain boolean oracles (text/length/status) and the Oracle
    ``conditional-error`` mode, both modeled as ``technique="boolean"``."""
    configuration = ctx.configuration

    if configuration.attack_mode == "conditional-error":
        detector: Detector = ErrorDetector(
            error_text=configuration.error_text or configuration.detector_value or None,
            error_regex=configuration.error_regex,
            error_status=configuration.error_status,
        )
        payload_builder: PayloadBuilder = ConditionalErrorPayloadBuilder.for_oracle(
            table=configuration.table,
            user_column=configuration.user_column,
            username=configuration.username,
        )
        condition_builder = OracleAsciiSubstringConditionBuilder()
        strategy = _build_strategy(configuration, "<=")
    else:
        detector = _BOOLEAN_DETECTOR_FACTORIES[configuration.detector](configuration)
        payload_builder = BooleanPayloadBuilder()
        condition_builder = AsciiSubstringConditionBuilder()
        strategy = _build_strategy(configuration)

    extractor = BlindExtractor(
        http_client=ctx.http_client,
        condition_builder=condition_builder,
        payload_builder=_apply_tampers(configuration, payload_builder),
        injection_point=ctx.injection_point,
        detector=detector,
        search_strategy=strategy,
        base_request=ctx.request,
        charset=configuration.charset,
        max_length=configuration.max_length,
        delay=configuration.delay,
        on_progress=ctx.on_progress,
    )
    return BooleanTechnique(extractor)


def _build_time_technique(ctx: _BuildContext) -> Technique:
    configuration = ctx.configuration
    sleep_seconds = configuration.sleep_seconds
    timing_threshold = configuration.timing_threshold
    if sleep_seconds is None or timing_threshold is None:
        raise ValueError("time-based techniques require sleep_seconds and timing_threshold")

    timing = TimingConfig(
        sleep_seconds=sleep_seconds,
        threshold_seconds=timing_threshold,
        baseline_seconds=configuration.timing_baseline,
        tolerance_seconds=configuration.timing_tolerance,
        samples=configuration.calibration_samples,
    )
    detector = TimingDetector(
        threshold_seconds=timing.threshold_seconds,
        baseline_seconds=timing.baseline_seconds,
        tolerance_seconds=timing.tolerance_seconds,
    )
    payload_builder = TimePayloadBuilder.for_dialect(configuration.dialect, timing.sleep_seconds)
    condition_builder = AsciiSubstringConditionBuilder()
    strategy = _build_strategy(configuration, "<=")

    extractor = BlindExtractor(
        http_client=ctx.http_client,
        condition_builder=condition_builder,
        payload_builder=_apply_tampers(configuration, payload_builder),
        injection_point=ctx.injection_point,
        detector=detector,
        search_strategy=strategy,
        base_request=ctx.request,
        charset=configuration.charset,
        max_length=configuration.max_length,
        delay=configuration.delay,
        on_progress=ctx.on_progress,
    )
    return TimeBasedTechnique(extractor, timing)


def _build_visible_error_technique(ctx: _BuildContext) -> Technique:
    configuration = ctx.configuration
    default_pattern = r'invalid input syntax for type integer:\s*"(?P<value>.*?)"'
    value_pattern = configuration.error_value_regex or default_pattern
    signal_pattern = configuration.error_regex or value_pattern

    detector = ErrorDetector(
        error_text=configuration.error_text,
        error_regex=signal_pattern,
        error_status=configuration.error_status,
    )
    return VisibleErrorTechnique(
        http_client=ctx.http_client,
        payload_builder=_apply_tampers(configuration, PostgresCastPayloadBuilder()),
        injection_point=ctx.injection_point,
        error_detector=detector,
        value_extractor=ErrorValueExtractor(value_pattern),
        base_request=ctx.request,
    )


# The technique registry: add a new technique by adding a builder function
# above and one entry here -- never by growing an if/elif chain.
_TECHNIQUE_BUILDERS: dict[str, Callable[[_BuildContext], Technique]] = {
    "boolean": _build_boolean_technique,
    "time": _build_time_technique,
    "visible-error": _build_visible_error_technique,
}


def build_attack_engine(
    configuration: AttackConfiguration,
    *,
    on_progress=None,
) -> BlindAttackEngine:
    """Create the complete production object graph from configuration.

    Performs no network I/O itself -- it only wires adapters together.
    ``on_progress`` is forwarded, unmodified, to every ``BlindExtractor``
    built for a boolean/time technique; this is the seam checkpoint
    persistence hooks into (see ``core.checkpoint``). This module has no
    idea whether ``on_progress`` writes anywhere.
    """
    ctx = _BuildContext(
        configuration=configuration,
        http_client=_build_http_client(configuration),
        injection_point=_build_injection_point(configuration),
        request=_build_request(configuration),
        on_progress=on_progress,
    )
    try:
        builder = _TECHNIQUE_BUILDERS[configuration.technique]
    except KeyError:
        raise ValueError(
            f"No technique builder registered for {configuration.technique!r}. "
            f"Available: {', '.join(sorted(_TECHNIQUE_BUILDERS))}. "
            "('auto' must be resolved via config.fingerprint() before reaching here.)"
        ) from None

    return _finish_engine(configuration, lambda: builder(ctx))


def _finish_engine(configuration: AttackConfiguration, build_technique) -> BlindAttackEngine:
    """Wire the sequential or parallel engine depending on ``max_workers``.

    With ``max_workers == 1`` (the default), behavior is unchanged from
    before this factory accepted a builder callable: one technique instance
    is built and used for everything. With ``max_workers > 1``, that same
    callable becomes the ``extractor_factory`` the engine uses to mint one
    fresh instance per expression in its thread pool.
    """
    primary = build_technique()
    if configuration.max_workers <= 1:
        return BlindAttackEngine(primary)
    return BlindAttackEngine(
        primary,
        extractor_factory=build_technique,
        max_workers=configuration.max_workers,
    )
