"""Tests for configuration composition."""

import unittest
from unittest.mock import Mock, patch

from config import build_attack_engine, calibrate_timing, fingerprint
from core import BlindAttackEngine
from models import AttackConfiguration, Target


class ConfigurationFactoryTests(unittest.TestCase):
    def test_builds_engine_from_text_configuration(self) -> None:
        configuration = AttackConfiguration(
            target=Target("https://example.test", query={"tracking": "base"}),
            parameter="tracking",
            detector_value="TRUE",
        )

        engine = build_attack_engine(configuration)

        self.assertIsInstance(engine, BlindAttackEngine)

    def test_builds_length_and_status_configurations(self) -> None:
        target = Target("https://example.test", query={"tracking": "base"})
        for values in (
            {"detector": "length", "expected_length": 10},
            {"detector": "status", "expected_status": 200},
        ):
            with self.subTest(values=values):
                engine = build_attack_engine(
                    AttackConfiguration(target, parameter="tracking", **values)
                )
                self.assertIsInstance(engine, BlindAttackEngine)

    def test_builds_conditional_error_configuration(self) -> None:
        configuration = AttackConfiguration(
            Target("https://example.test", cookies={"TrackingId": "base"}),
            parameter="TrackingId",
            injection_location="cookie",
            attack_mode="conditional-error",
            error_regex=r"ORA-\d+",
        )
        self.assertIsInstance(build_attack_engine(configuration), BlindAttackEngine)

    def test_builds_visible_error_configuration(self) -> None:
        configuration = AttackConfiguration(
            Target("https://example.test", cookies={"TrackingId": "base"}),
            parameter="TrackingId",
            injection_location="cookie",
            injection_mode="replace",
            technique="visible-error",
            attack_mode="visible-error",
            dialect="postgres",
            detector="error",
        )

        self.assertIsInstance(build_attack_engine(configuration), BlindAttackEngine)

    def test_rejects_visible_error_with_other_dialect(self) -> None:
        with self.assertRaises(ValueError):
            AttackConfiguration(
                Target("https://example.test", cookies={"TrackingId": "base"}),
                parameter="TrackingId",
                injection_location="cookie",
                technique="visible-error",
                attack_mode="visible-error",
                dialect="mysql",
                detector="error",
            )

    def test_builds_time_based_configuration(self) -> None:
        configuration = AttackConfiguration(
            target=Target("https://example.test", query={"tracking": "base"}),
            parameter="tracking",
            technique="time",
            dialect="mysql",
            sleep_seconds=3.0,
            timing_threshold=2.0,
            timing_baseline=0.5,
            timing_tolerance=0.25,
        )

        self.assertIsInstance(build_attack_engine(configuration), BlindAttackEngine)

    def test_builds_time_based_configuration_for_postgres_dialect(self) -> None:
        configuration = AttackConfiguration(
            target=Target("https://example.test", query={"tracking": "base"}),
            parameter="tracking",
            technique="time",
            dialect="postgres",
            sleep_seconds=3.0,
            timing_threshold=2.0,
        )

        self.assertIsInstance(build_attack_engine(configuration), BlindAttackEngine)

    def test_rejects_time_based_configuration_with_boolean_detector(self) -> None:
        with self.assertRaises(ValueError):
            AttackConfiguration(
                target=Target("https://example.test", query={"tracking": "base"}),
                parameter="tracking",
                technique="time",
                dialect="mysql",
                detector="status",
                expected_status=200,
                sleep_seconds=3.0,
                timing_threshold=2.0,
            )

    def test_rejects_boolean_configuration_with_timing_detector(self) -> None:
        with self.assertRaises(ValueError):
            AttackConfiguration(
                target=Target("https://example.test", query={"tracking": "base"}),
                parameter="tracking",
                technique="boolean",
                detector="timing",
                detector_value="TRUE",
            )

    def test_builds_engine_with_rate_limit_and_multiple_workers(self) -> None:
        configuration = AttackConfiguration(
            target=Target("https://example.test", query={"tracking": "base"}),
            parameter="tracking",
            detector_value="TRUE",
            rate_limit=5.0,
            max_workers=3,
        )

        self.assertIsInstance(build_attack_engine(configuration), BlindAttackEngine)

    def test_rejects_multiple_workers_for_time_technique(self) -> None:
        with self.assertRaises(ValueError):
            AttackConfiguration(
                target=Target("https://example.test", query={"tracking": "base"}),
                parameter="tracking",
                technique="time",
                dialect="mysql",
                sleep_seconds=3.0,
                timing_threshold=2.0,
                max_workers=2,
            )

    @patch("transport.requests_client.requests.Session")
    def test_calibrate_timing_measures_latency_without_configuring_threshold(
        self, session_factory: Mock
    ) -> None:
        request_call = session_factory.return_value.request
        request_call.return_value = Mock(status_code=200, text="ok", headers={})
        configuration = AttackConfiguration(
            target=Target("https://example.test", query={"tracking": "base"}),
            parameter="tracking",
            technique="time",
            dialect="mysql",
            sleep_seconds=3.0,
            timing_threshold=2.0,
            auto_calibrate=True,
            calibration_samples=4,
        )

        baseline, tolerance = calibrate_timing(configuration)

        self.assertEqual(request_call.call_count, 5)  # 1 warmup + 4 samples
        self.assertGreaterEqual(baseline, 0.0)
        self.assertGreaterEqual(tolerance, 0.0)

    def test_calibrate_timing_rejects_non_time_technique(self) -> None:
        configuration = AttackConfiguration(
            target=Target("https://example.test", query={"tracking": "base"}),
            parameter="tracking",
            detector_value="TRUE",
        )

        with self.assertRaises(ValueError):
            calibrate_timing(configuration)

    def test_builds_engine_with_tamper_chain(self) -> None:
        configuration = AttackConfiguration(
            target=Target("https://example.test", query={"tracking": "base"}),
            parameter="tracking",
            detector_value="TRUE",
            tampers=("space2comment", "randomcase"),
        )

        self.assertIsInstance(build_attack_engine(configuration), BlindAttackEngine)

    def test_rejects_unknown_tamper_name_at_build_time(self) -> None:
        configuration = AttackConfiguration(
            target=Target("https://example.test", query={"tracking": "base"}),
            parameter="tracking",
            detector_value="TRUE",
            tampers=("not-a-real-tamper",),
        )

        with self.assertRaises(ValueError):
            build_attack_engine(configuration)

    def test_builds_engine_with_header_mutation_enabled(self) -> None:
        configuration = AttackConfiguration(
            target=Target("https://example.test", query={"tracking": "base"}),
            parameter="tracking",
            detector_value="TRUE",
            random_agent=True,
            random_forwarded_for=True,
        )

        self.assertIsInstance(build_attack_engine(configuration), BlindAttackEngine)

    @patch("transport.requests_client.requests.Session")
    def test_fingerprint_composes_real_adapters_without_network(
        self, session_factory: Mock
    ) -> None:
        request_call = session_factory.return_value.request
        request_call.return_value = Mock(status_code=200, text="same", headers={})
        configuration = AttackConfiguration(
            target=Target("https://example.test", query={"tracking": "base"}),
            parameter="tracking",
            technique="auto",
        )

        result = fingerprint(configuration)

        self.assertEqual(result.confidence, "none")  # identical mocked responses throughout
        self.assertTrue(request_call.called)

    def test_rejects_unregistered_technique_instead_of_guessing(self) -> None:
        # technique="auto" is meant to be resolved by config.fingerprint()
        # before reaching build_attack_engine; calling it directly must fail
        # loudly instead of silently falling through to some other builder.
        configuration = AttackConfiguration(
            target=Target("https://example.test", query={"tracking": "base"}),
            parameter="tracking",
            technique="auto",
        )

        with self.assertRaises(ValueError):
            build_attack_engine(configuration)

    def test_time_based_configuration_normalizes_to_timing_detector(self) -> None:
        configuration = AttackConfiguration(
            target=Target("https://example.test", query={"tracking": "base"}),
            parameter="tracking",
            technique="time",
            dialect="mysql",
            sleep_seconds=3.0,
            timing_threshold=2.0,
        )

        self.assertEqual(configuration.detector, "timing")


if __name__ == "__main__":
    unittest.main()