"""Tests for immutable domain models."""

import unittest
from dataclasses import FrozenInstanceError

from models import (
    AttackConfiguration,
    AttackResult,
    CharacterResult,
    HttpResponseData,
    RequestData,
    Target,
)


class TargetTests(unittest.TestCase):
    def test_normalizes_method_and_freezes_mappings(self) -> None:
        target = Target("https://example.test/search", method="post", query={"q": "x"})

        self.assertEqual(target.method, "POST")
        with self.assertRaises(TypeError):
            target.query["q"] = "changed"  # type: ignore[index]
        with self.assertRaises(FrozenInstanceError):
            target.url = "https://other.test"  # type: ignore[misc]

    def test_rejects_invalid_url_and_method(self) -> None:
        with self.assertRaises(ValueError):
            Target("not-a-url")
        with self.assertRaises(ValueError):
            Target("https://example.test", method="PUT")


class ConfigurationTests(unittest.TestCase):
    def test_rejects_invalid_runtime_values(self) -> None:
        target = Target("https://example.test")
        for kwargs in ({"charset": ""}, {"timeout": 0}, {"delay": -1}, {"parameter": ""}):
            with self.subTest(kwargs=kwargs), self.assertRaises(ValueError):
                AttackConfiguration(target, **kwargs)

    def test_validates_detector_and_strategy_configuration(self) -> None:
        target = Target("https://example.test")
        base = {"parameter": "tracking"}
        with self.assertRaises(ValueError):
            AttackConfiguration(target, **base)
        with self.assertRaises(ValueError):
            AttackConfiguration(target, detector="length", expected_length=None, **base)
        with self.assertRaises(ValueError):
            AttackConfiguration(target, strategy="unknown", detector_value="ok", **base)

    def test_validates_conditional_error_configuration(self) -> None:
        target = Target("https://example.test")
        configuration = AttackConfiguration(
            target,
            parameter="TrackingId",
            attack_mode="conditional-error",
            error_text="ORA-01476",
        )
        self.assertEqual(configuration.column, "password")
        with self.assertRaises(ValueError):
            AttackConfiguration(
                target,
                parameter="TrackingId",
                attack_mode="conditional-error",
            )
        with self.assertRaises(ValueError):
            AttackConfiguration(
                target,
                parameter="TrackingId",
                attack_mode="conditional-error",
                dialect="postgres",
                error_status=500,
            )
        with self.assertRaises(ValueError):
            AttackConfiguration(
                target,
                parameter="tracking",
                detector="error",
                detector_value="ORA-01476",
            )

    def test_auto_technique_skips_technique_specific_validation(self) -> None:
        target = Target("https://example.test")
        configuration = AttackConfiguration(target, parameter="tracking", technique="auto")

        self.assertEqual(configuration.technique, "auto")
        # Generic fields still validate even for "auto".
        with self.assertRaises(ValueError):
            AttackConfiguration(target, parameter="tracking", technique="auto", max_length=0)

    def test_rejects_unknown_technique(self) -> None:
        target = Target("https://example.test")
        with self.assertRaises(ValueError):
            AttackConfiguration(target, parameter="tracking", technique="not-a-technique")


class HttpModelTests(unittest.TestCase):
    def test_response_exposes_decoded_content_length(self) -> None:
        response = HttpResponseData(200, "hello")
        self.assertEqual(response.content_length, 5)

    def test_request_and_response_validate_values(self) -> None:
        with self.assertRaises(ValueError):
            RequestData("https://example.test", method="DELETE")
        with self.assertRaises(ValueError):
            HttpResponseData(700, "")


class ResultTests(unittest.TestCase):
    def test_character_result_validates_position_and_character(self) -> None:
        with self.assertRaises(ValueError):
            CharacterResult(0, "a")
        with self.assertRaises(ValueError):
            CharacterResult(1, "ab")

    def test_attack_result_freezes_mapping(self) -> None:
        result = AttackResult()
        with self.assertRaises(TypeError):
            result.extractions["x"] = None  # type: ignore[index]


if __name__ == "__main__":
    unittest.main()
