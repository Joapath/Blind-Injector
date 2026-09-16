"""Tests for configuration composition."""

import unittest

from config import build_attack_engine
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