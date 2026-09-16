"""Tests for pure response detectors."""

import unittest

from detection import ErrorDetector, LengthDetector, StatusCodeDetector, TextDetector
from models import HttpResponseData


class TextDetectorTests(unittest.TestCase):
    def test_detects_expected_text(self) -> None:
        detector = TextDetector("Welcome back")
        self.assertTrue(detector.is_true(HttpResponseData(200, "Welcome back, user")))
        self.assertFalse(detector.is_true(HttpResponseData(200, "Access denied")))

    def test_supports_case_insensitive_matching(self) -> None:
        detector = TextDetector("welcome back", case_sensitive=False)
        self.assertTrue(detector.is_true(HttpResponseData(200, "WELCOME BACK")))

    def test_rejects_empty_expected_text(self) -> None:
        with self.assertRaises(ValueError):
            TextDetector("")


class LengthDetectorTests(unittest.TestCase):
    def test_matches_exact_length_by_default(self) -> None:
        detector = LengthDetector(expected_length=5)
        self.assertTrue(detector.is_true(HttpResponseData(200, "hello")))
        self.assertFalse(detector.is_true(HttpResponseData(200, "hello!")))

    def test_applies_configured_tolerance(self) -> None:
        detector = LengthDetector(expected_length=100, tolerance=2)
        self.assertTrue(detector.is_true(HttpResponseData(200, "x" * 102)))
        self.assertFalse(detector.is_true(HttpResponseData(200, "x" * 103)))

    def test_rejects_negative_configuration(self) -> None:
        with self.assertRaises(ValueError):
            LengthDetector(-1)
        with self.assertRaises(ValueError):
            LengthDetector(1, tolerance=-1)


class StatusCodeDetectorTests(unittest.TestCase):
    def test_matches_expected_status(self) -> None:
        detector = StatusCodeDetector(200)
        self.assertTrue(detector.is_true(HttpResponseData(200, "ok")))
        self.assertFalse(detector.is_true(HttpResponseData(403, "forbidden")))

    def test_rejects_invalid_status(self) -> None:
        with self.assertRaises(ValueError):
            StatusCodeDetector(99)
        with self.assertRaises(ValueError):
            StatusCodeDetector(600)


class ErrorDetectorTests(unittest.TestCase):
    def test_detects_error_pattern(self) -> None:
        detector = ErrorDetector("ORA-01476")
        self.assertTrue(detector.is_true(HttpResponseData(500, "ORA-01476: divisor is equal to zero")))
        self.assertFalse(detector.is_true(HttpResponseData(200, "OK")))

    def test_rejects_empty_error_value(self) -> None:
        with self.assertRaises(ValueError):
            ErrorDetector("")

    def test_supports_regex_and_status_signals(self) -> None:
        regex_detector = ErrorDetector(error_regex=r"ORA-\d+")
        self.assertTrue(regex_detector.is_true(HttpResponseData(200, "ORA-01476")))
        self.assertFalse(regex_detector.is_true(HttpResponseData(200, "OK")))

        status_detector = ErrorDetector(error_status=500)
        self.assertTrue(status_detector.is_true(HttpResponseData(500, "server error")))
        self.assertFalse(status_detector.is_true(HttpResponseData(200, "server error")))

    def test_prioritizes_regex_over_text_and_rejects_invalid_configuration(self) -> None:
        detector = ErrorDetector(error_text="wrong", error_regex="right")
        self.assertTrue(detector.is_true(HttpResponseData(200, "right")))
        self.assertFalse(detector.is_true(HttpResponseData(200, "wrong")))
        with self.assertRaises(ValueError):
            ErrorDetector()
        with self.assertRaises(ValueError):
            ErrorDetector(error_status=99)
        with self.assertRaises(Exception):
            ErrorDetector(error_regex="[")


if __name__ == "__main__":
    unittest.main()
