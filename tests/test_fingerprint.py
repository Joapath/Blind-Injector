"""Unit tests for heuristic technique/detector fingerprinting."""

import unittest
from collections.abc import Callable

from core.fingerprint import (
    BaselineSnapshot,
    TechniqueFingerprinter,
    _detect_waf,
    _find_distinguishing_signal,
)
from models import HttpResponseData, RequestData
from payloads import QueryParameterInjectionPoint
from transport import HttpClient


def _is_true_condition(payload: str) -> bool:
    return "(1=1)" in payload


def _is_time_mysql(payload: str) -> bool:
    return "SLEEP(" in payload


def _is_time_postgres(payload: str) -> bool:
    return "pg_sleep(" in payload


def _is_dialect_probe(payload: str) -> bool:
    return any(marker in payload for marker in ("pg_catalog", "database()", "v$version"))


def _is_malformed(payload: str) -> bool:
    return "SELECT 1 FROM" in payload and not _is_dialect_probe(payload)


def _is_baseline(payload: str) -> bool:
    return payload == "base"


class ScriptedHttpClient(HttpClient):
    """Drive the fingerprinter with a scenario-specific responder function."""

    def __init__(self, responder: Callable[[str], HttpResponseData]) -> None:
        self._responder = responder
        self.requests: list[RequestData] = []

    def send(self, request: RequestData) -> HttpResponseData:
        self.requests.append(request)
        return self._responder(request.query["tracking"])


def build_fingerprinter(responder: Callable[[str], HttpResponseData]) -> tuple[
    TechniqueFingerprinter, ScriptedHttpClient
]:
    client = ScriptedHttpClient(responder)
    fingerprinter = TechniqueFingerprinter(
        http_client=client,
        injection_point=QueryParameterInjectionPoint("tracking"),
        base_request=RequestData("https://example.test/filter", query={"tracking": "base"}),
        probe_sleep_seconds=1.5,
    )
    return fingerprinter, client


# ---------------------------------------------------------------------------
# Baseline tests
# ---------------------------------------------------------------------------


class BaselineTests(unittest.TestCase):
    def test_baseline_captured_before_probes(self) -> None:
        calls: list[str] = []

        def responder(payload: str) -> HttpResponseData:
            calls.append(payload)
            return HttpResponseData(200, "same", elapsed_seconds=0.02)

        fingerprinter, _ = build_fingerprinter(responder)
        fingerprinter.run()

        self.assertEqual(calls[0], "base")

    def test_baseline_failure_does_not_abort(self) -> None:
        first_call = True

        def responder(payload: str) -> HttpResponseData:
            nonlocal first_call
            if first_call:
                first_call = False
                raise ConnectionError("network down")
            return HttpResponseData(200, "same", elapsed_seconds=0.02)

        fingerprinter, _ = build_fingerprinter(responder)
        result = fingerprinter.run()

        self.assertEqual(result.confidence, "none")
        self.assertIsNone(fingerprinter._baseline)


# ---------------------------------------------------------------------------
# Boolean fingerprint tests
# ---------------------------------------------------------------------------


class BooleanFingerprintTests(unittest.TestCase):
    def test_detects_status_based_oracle(self) -> None:
        def responder(payload: str) -> HttpResponseData:
            if _is_baseline(payload):
                return HttpResponseData(200, "normal page")
            if _is_time_mysql(payload) or _is_time_postgres(payload) or _is_malformed(payload):
                return HttpResponseData(200, "neutral")
            status = 200 if (_is_true_condition(payload) and not _is_dialect_probe(payload)) else 403
            return HttpResponseData(status, "body")

        fingerprinter, client = build_fingerprinter(responder)
        result = fingerprinter.run()

        self.assertEqual(result.technique, "boolean")
        self.assertEqual(result.detector, "status")
        self.assertEqual(result.expected_status, 200)
        self.assertEqual(result.confidence, "confirmed")
        self.assertIsNone(result.dialect)
        self.assertEqual(result.payload_shape, ("' AND (", ")--"))
        # baseline + true/false twice (probe + confirm) + 3 dialect probes = 8
        self.assertEqual(len(client.requests), 8)

    def test_detects_length_based_oracle(self) -> None:
        def responder(payload: str) -> HttpResponseData:
            if _is_baseline(payload):
                return HttpResponseData(200, "A" * 50)
            if _is_time_mysql(payload) or _is_time_postgres(payload) or _is_malformed(payload):
                return HttpResponseData(200, "neutral")
            text = "A" * 50 if (_is_true_condition(payload) and not _is_dialect_probe(payload)) else "B" * 10
            return HttpResponseData(200, text)

        fingerprinter, _ = build_fingerprinter(responder)
        result = fingerprinter.run()

        self.assertEqual(result.technique, "boolean")
        self.assertEqual(result.detector, "length")
        self.assertEqual(result.expected_length, 50)
        self.assertEqual(result.confidence, "confirmed")

    def test_detects_text_based_oracle(self) -> None:
        def responder(payload: str) -> HttpResponseData:
            if _is_baseline(payload):
                return HttpResponseData(200, "page content")
            if _is_time_mysql(payload) or _is_time_postgres(payload) or _is_malformed(payload):
                return HttpResponseData(200, "neutral")
            text = "Welcome back!!" if _is_true_condition(payload) else "Access denied!"
            return HttpResponseData(200, text)

        fingerprinter, _ = build_fingerprinter(responder)
        result = fingerprinter.run()

        self.assertEqual(result.technique, "boolean")
        self.assertEqual(result.detector, "text")
        self.assertIsNotNone(result.detector_value)
        self.assertIn(result.detector_value, "Welcome back!!")
        self.assertNotIn(result.detector_value, "Access denied!")
        self.assertEqual(result.confidence, "confirmed")

    def test_detects_dialect_of_boolean_oracle(self) -> None:
        def responder(payload: str) -> HttpResponseData:
            if _is_baseline(payload):
                return HttpResponseData(200, "page content")
            if _is_time_mysql(payload) or _is_time_postgres(payload) or _is_malformed(payload):
                return HttpResponseData(200, "neutral")
            truthy = _is_true_condition(payload) or "pg_catalog" in payload
            text = "Welcome back!!" if truthy else "Access denied!"
            return HttpResponseData(200, text)

        fingerprinter, _ = build_fingerprinter(responder)
        result = fingerprinter.run()

        self.assertEqual(result.technique, "boolean")
        self.assertEqual(result.detector, "text")
        self.assertEqual(result.dialect, "postgres")
        self.assertIn("dialect probed as postgres", result.notes)

    def test_boolean_oracle_without_matching_dialect_leaves_dialect_none(self) -> None:
        def responder(payload: str) -> HttpResponseData:
            if _is_baseline(payload):
                return HttpResponseData(200, "page content")
            if _is_time_mysql(payload) or _is_time_postgres(payload) or _is_malformed(payload):
                return HttpResponseData(200, "neutral")
            truthy = _is_true_condition(payload) and not _is_dialect_probe(payload)
            text = "Welcome back!!" if truthy else "Access denied!"
            return HttpResponseData(200, text)

        fingerprinter, _ = build_fingerprinter(responder)
        result = fingerprinter.run()

        self.assertEqual(result.technique, "boolean")
        self.assertIsNone(result.dialect)


# ---------------------------------------------------------------------------
# Multiple payload shapes tests
# ---------------------------------------------------------------------------


class PayloadShapeTests(unittest.TestCase):
    def test_tries_numeric_shape_when_quoted_fails(self) -> None:
        """First two shapes fail, third (numeric) succeeds."""
        def _is_numeric_shape(payload: str) -> bool:
            # Numeric shape: "base AND (...)" — no quote before AND
            return "base AND (" in payload

        def responder(payload: str) -> HttpResponseData:
            if _is_baseline(payload):
                return HttpResponseData(200, "normal")
            if _is_numeric_shape(payload) and "(1=1)" in payload:
                return HttpResponseData(200, "big" * 20)
            if _is_numeric_shape(payload) and "(1=2)" in payload:
                return HttpResponseData(200, "small")
            return HttpResponseData(200, "same", elapsed_seconds=0.02)

        fingerprinter, _ = build_fingerprinter(responder)
        result = fingerprinter.run()

        self.assertEqual(result.technique, "boolean")
        self.assertEqual(result.payload_shape, (" AND (", ")--"))
        self.assertIn("payload shape", " ".join(result.notes))

    def test_default_shape_has_no_shape_note(self) -> None:
        """When the default shape works, notes don't mention shape."""
        def responder(payload: str) -> HttpResponseData:
            if _is_baseline(payload):
                return HttpResponseData(200, "normal")
            if _is_true_condition(payload) and not _is_dialect_probe(payload):
                return HttpResponseData(200, "big" * 20)
            return HttpResponseData(200, "small", elapsed_seconds=0.02)

        fingerprinter, _ = build_fingerprinter(responder)
        result = fingerprinter.run()

        self.assertEqual(result.payload_shape, ("' AND (", ")--"))
        self.assertFalse(any("payload shape" in n for n in result.notes))


# ---------------------------------------------------------------------------
# Timing fingerprint tests
# ---------------------------------------------------------------------------


class TimeFingerprintTests(unittest.TestCase):
    def test_detects_mysql_timing_oracle_when_boolean_is_inconclusive(self) -> None:
        def responder(payload: str) -> HttpResponseData:
            if _is_baseline(payload):
                return HttpResponseData(200, "normal", elapsed_seconds=0.05)
            if _is_time_mysql(payload):
                elapsed = 2.0 if _is_true_condition(payload) else 0.05
                return HttpResponseData(200, "x", elapsed_seconds=elapsed)
            return HttpResponseData(200, "same", elapsed_seconds=0.05)

        fingerprinter, _ = build_fingerprinter(responder)
        result = fingerprinter.run()

        self.assertEqual(result.technique, "time")
        self.assertEqual(result.detector, "timing")
        self.assertEqual(result.dialect, "mysql")
        self.assertEqual(result.sleep_seconds, 1.5)
        self.assertEqual(result.confidence, "confirmed")

    def test_detects_postgres_timing_oracle_after_mysql_is_tried_and_fails(self) -> None:
        def responder(payload: str) -> HttpResponseData:
            if _is_baseline(payload):
                return HttpResponseData(200, "normal", elapsed_seconds=0.05)
            if _is_time_postgres(payload):
                elapsed = 2.0 if _is_true_condition(payload) else 0.05
                return HttpResponseData(200, "x", elapsed_seconds=elapsed)
            return HttpResponseData(200, "same", elapsed_seconds=0.05)

        fingerprinter, _ = build_fingerprinter(responder)
        result = fingerprinter.run()

        self.assertEqual(result.technique, "time")
        self.assertEqual(result.dialect, "postgres")
        self.assertEqual(result.confidence, "confirmed")


# ---------------------------------------------------------------------------
# Error fingerprint tests
# ---------------------------------------------------------------------------


class ErrorFingerprintTests(unittest.TestCase):
    def test_detects_oracle_error_signature_and_auto_configures(self) -> None:
        def responder(payload: str) -> HttpResponseData:
            if _is_baseline(payload):
                return HttpResponseData(200, "normal page")
            if _is_malformed(payload):
                return HttpResponseData(200, "ORA-00936: missing expression")
            return HttpResponseData(200, "same", elapsed_seconds=0.02)

        fingerprinter, _ = build_fingerprinter(responder)
        result = fingerprinter.run()

        self.assertEqual(result.technique, "boolean")
        self.assertEqual(result.detector, "error")
        self.assertEqual(result.attack_mode, "conditional-error")
        self.assertEqual(result.dialect, "oracle")
        self.assertIsNotNone(result.error_regex)
        self.assertEqual(result.confidence, "confirmed")

    def test_detects_postgres_error_signature_but_does_not_auto_configure(self) -> None:
        def responder(payload: str) -> HttpResponseData:
            if _is_baseline(payload):
                return HttpResponseData(200, "normal page")
            if _is_malformed(payload):
                return HttpResponseData(200, 'ERROR:  syntax error at or near "FROM"')
            return HttpResponseData(200, "same", elapsed_seconds=0.02)

        fingerprinter, _ = build_fingerprinter(responder)
        result = fingerprinter.run()

        self.assertIsNone(result.technique)
        self.assertEqual(result.confidence, "none")
        self.assertEqual(result.dialect, "postgres")
        self.assertTrue(any("postgres" in note for note in result.notes))


# ---------------------------------------------------------------------------
# WAF detection tests
# ---------------------------------------------------------------------------


class WafDetectionTests(unittest.TestCase):
    def test_detects_waf_by_status_code(self) -> None:
        baseline = BaselineSnapshot(status_code=200, content_length=500, body_hash="abc")
        responses = [HttpResponseData(403, "Forbidden")]
        detected, reasons = _detect_waf(baseline, responses)
        self.assertTrue(detected)
        self.assertTrue(any("403" in r for r in reasons))

    def test_no_waf_when_baseline_also_returns_403(self) -> None:
        baseline = BaselineSnapshot(status_code=403, content_length=50, body_hash="abc")
        responses = [HttpResponseData(403, "Forbidden")]
        detected, reasons = _detect_waf(baseline, responses)
        self.assertFalse(any("403" in r for r in reasons))

    def test_detects_waf_by_header(self) -> None:
        baseline = BaselineSnapshot(status_code=200, content_length=500, body_hash="abc")
        responses = [HttpResponseData(200, "ok", headers={"cf-ray": "abc123"})]
        detected, reasons = _detect_waf(baseline, responses)
        self.assertTrue(detected)
        self.assertTrue(any("Cloudflare" in r for r in reasons))

    def test_detects_waf_by_body_signature(self) -> None:
        baseline = BaselineSnapshot(status_code=200, content_length=500, body_hash="abc")
        responses = [HttpResponseData(200, "Access Denied. Please try again later.")]
        detected, reasons = _detect_waf(baseline, responses)
        self.assertTrue(detected)
        self.assertTrue(any("access denied" in r for r in reasons))

    def test_detects_uniform_probe_responses_differing_from_baseline(self) -> None:
        baseline = BaselineSnapshot(status_code=200, content_length=500, body_hash="abc")
        responses = [
            HttpResponseData(200, "blocked" * 5),
            HttpResponseData(200, "blocked" * 5),
            HttpResponseData(200, "blocked" * 5),
        ]
        detected, reasons = _detect_waf(baseline, responses)
        self.assertTrue(detected)
        self.assertTrue(any("uniform" in r or "identical" in r for r in reasons))

    def test_no_waf_with_empty_responses(self) -> None:
        baseline = BaselineSnapshot(status_code=200, content_length=500, body_hash="abc")
        detected, reasons = _detect_waf(baseline, [])
        self.assertFalse(detected)
        self.assertEqual(reasons, [])

    def test_waf_integrated_in_fingerprinter(self) -> None:
        """WAF headers in probe responses get reported in the result."""
        def responder(payload: str) -> HttpResponseData:
            if _is_baseline(payload):
                return HttpResponseData(200, "normal page")
            return HttpResponseData(
                200, "same", headers={"cf-ray": "abc123"}, elapsed_seconds=0.02
            )

        fingerprinter, _ = build_fingerprinter(responder)
        result = fingerprinter.run()

        self.assertTrue(result.waf_detected)
        self.assertTrue(any("WAF" in n for n in result.notes))

    def test_waf_with_successful_boolean_detection(self) -> None:
        """WAF detected but oracle still works — report both."""
        def responder(payload: str) -> HttpResponseData:
            if _is_baseline(payload):
                return HttpResponseData(200, "normal page")
            if _is_true_condition(payload) and not _is_dialect_probe(payload):
                return HttpResponseData(200, "big" * 20, headers={"cf-ray": "x"})
            return HttpResponseData(200, "small", headers={"cf-ray": "x"}, elapsed_seconds=0.02)

        fingerprinter, _ = build_fingerprinter(responder)
        result = fingerprinter.run()

        self.assertEqual(result.technique, "boolean")
        self.assertTrue(result.waf_detected)
        self.assertTrue(any("tamper" in n for n in result.notes))


# ---------------------------------------------------------------------------
# Distinguishing signal tests
# ---------------------------------------------------------------------------


class DistinguishingSignalTests(unittest.TestCase):
    def test_finds_signal_in_clearly_different_texts(self) -> None:
        result = _find_distinguishing_signal("Welcome back!!", "Access denied!")
        self.assertIsNotNone(result)
        self.assertIn(result, "Welcome back!!")
        self.assertNotIn(result, "Access denied!")

    def test_returns_none_for_identical_texts(self) -> None:
        result = _find_distinguishing_signal("same text", "same text")
        self.assertIsNone(result)

    def test_filters_dynamic_uuid_tokens(self) -> None:
        uuid = "550e8400-e29b-41d4-a716-446655440000"
        true_text = f"Welcome {uuid}"
        false_text = f"Denied {uuid}"
        result = _find_distinguishing_signal(true_text, false_text)
        self.assertIsNotNone(result)
        self.assertNotIn(uuid, result)

    def test_filters_hex_csrf_tokens(self) -> None:
        token = "a1b2c3d4e5f6a7b8c9d0e1f2a3b4c5d6"
        true_text = f"Welcome {token} back"
        false_text = f"Denied {token} away"
        result = _find_distinguishing_signal(true_text, false_text)
        self.assertIsNotNone(result)
        self.assertNotIn(token, result)

    def test_returns_none_when_only_dynamic_tokens_differ(self) -> None:
        result = _find_distinguishing_signal(
            "page nonce='abc123def456' end",
            "page nonce='xyz789uvw012' end",
        )
        self.assertIsNone(result)

    def test_respects_min_length(self) -> None:
        result = _find_distinguishing_signal("ab cd", "ef gh", min_length=5)
        self.assertIsNone(result)

    def test_html_like_content(self) -> None:
        true_html = '<div class="result"><h2>Product Found</h2><p>Details here</p></div>'
        false_html = '<div class="result"><h2>No Results</h2><p>Try again</p></div>'
        result = _find_distinguishing_signal(true_html, false_html)
        self.assertIsNotNone(result)
        self.assertIn(result, true_html)
        self.assertNotIn(result, false_html)


# ---------------------------------------------------------------------------
# No-signal tests
# ---------------------------------------------------------------------------


class NoSignalFingerprintTests(unittest.TestCase):
    def test_reports_no_confidence_when_nothing_distinguishes(self) -> None:
        def responder(_payload: str) -> HttpResponseData:
            return HttpResponseData(200, "always the same", elapsed_seconds=0.02)

        fingerprinter, _ = build_fingerprinter(responder)
        result = fingerprinter.run()

        self.assertIsNone(result.technique)
        self.assertEqual(result.confidence, "none")
        self.assertIsNone(result.dialect)


if __name__ == "__main__":
    unittest.main()
