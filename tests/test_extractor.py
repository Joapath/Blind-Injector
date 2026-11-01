"""Composition tests for the dependency-injected extractor."""

import re
import unittest
from collections.abc import Mapping

from core import BinarySearchStrategy, BlindExtractor, BruteForceStrategy
from detection import ErrorDetector, TextDetector
from models import CharacterResult, HttpResponseData, RequestData
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
        if "(1=1)" in payload:
            return HttpResponseData(200, "TRUE")
        if "(1=2)" in payload:
            return HttpResponseData(200, "FALSE")
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


def build_extractor(strategy, client, **kwargs):
    defaults = dict(
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
        pre_extract_length=False,
    )
    defaults.update(kwargs)
    return BlindExtractor(**defaults)


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

    def test_progress_log_includes_elapsed_and_eta_from_injected_clock(self) -> None:
        client = ConditionAwareFakeHttpClient({1: "a", 2: "b"})
        clock_values = iter([0.0, 1.0, 3.0])
        extractor = BlindExtractor(
            http_client=client,
            condition_builder=AsciiSubstringConditionBuilder(),
            payload_builder=BooleanPayloadBuilder(),
            injection_point=QueryParameterInjectionPoint("tracking"),
            detector=TextDetector("TRUE"),
            search_strategy=BruteForceStrategy(),
            base_request=RequestData("https://example.test/filter", query={"tracking": "base"}),
            charset="abc",
            max_length=3,
            clock=lambda: next(clock_values),
            pre_extract_length=False,
        )

        with self.assertLogs("core.extractor", level="INFO") as logs:
            extractor.extract("secret()")

        joined = "\n".join(logs.output)
        self.assertIn("Position 1/3 resolved as a", joined)
        self.assertIn("1.0s elapsed, ~2.0s remaining", joined)
        self.assertIn("Position 2/3 resolved as b", joined)
        self.assertIn("3.0s elapsed, ~1.5s remaining", joined)

    def test_rejects_extraction_when_request_budget_is_exceeded(self) -> None:
        client = ConditionAwareFakeHttpClient({1: "a"})
        extractor = BlindExtractor(
            http_client=client,
            condition_builder=AsciiSubstringConditionBuilder(),
            payload_builder=BooleanPayloadBuilder(),
            injection_point=QueryParameterInjectionPoint("tracking"),
            detector=TextDetector("TRUE"),
            search_strategy=BruteForceStrategy(),
            base_request=RequestData(
                "https://example.test/filter",
                query={"tracking": "base"},
            ),
            charset="abc",
            max_length=3,
            request_budget=1,
        )

        with self.assertRaises(RuntimeError):
            extractor.extract("secret()")

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

    def test_resumes_from_previously_resolved_characters(self) -> None:
        client = ConditionAwareFakeHttpClient({1: "a", 2: "b", 3: "c"})
        extractor = build_extractor(BruteForceStrategy(), client)

        resume_from = (CharacterResult(position=1, character="a", attempts=1),)
        result = extractor.extract("secret()", resume_from=resume_from)

        self.assertEqual(result.value, "abc")
        self.assertTrue(result.complete)
        self.assertEqual(result.characters[0], resume_from[0])
        # Position 1 was already known: never re-queried, extraction starts
        # straight at the position-2 length check.
        self.assertFalse(
            any(
                "LENGTH(secret())<1" in request.query["tracking"]
                for request in client.requests
            )
        )
        self.assertIn("LENGTH(secret())<2", client.requests[0].query["tracking"])

    def test_reports_progress_through_injected_callback(self) -> None:
        client = ConditionAwareFakeHttpClient({1: "a", 2: "b"})
        progress: list[tuple[str, tuple[CharacterResult, ...], bool]] = []
        extractor = BlindExtractor(
            http_client=client,
            condition_builder=AsciiSubstringConditionBuilder(),
            payload_builder=BooleanPayloadBuilder(),
            injection_point=QueryParameterInjectionPoint("tracking"),
            detector=TextDetector("TRUE"),
            search_strategy=BruteForceStrategy(),
            base_request=RequestData(
                "https://example.test/filter",
                query={"tracking": "base"},
            ),
            charset="abc",
            max_length=3,
            on_progress=lambda expression, characters, complete: progress.append(
                (expression, characters, complete)
            ),
        )

        result = extractor.extract("secret()")

        # One callback per resolved position, plus one final call carrying
        # the terminal `complete` flag used by checkpoint persistence.
        self.assertEqual(len(progress), 3)
        self.assertTrue(all(call[0] == "secret()" for call in progress))
        self.assertEqual([call[2] for call in progress], [False, False, True])
        self.assertEqual(progress[-1][1], result.characters)

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


class LengthPreExtractionTests(unittest.TestCase):
    def test_pre_extracts_length_and_uses_it_as_bound(self) -> None:
        client = ConditionAwareFakeHttpClient({1: "a", 2: "b"})
        extractor = build_extractor(
            BruteForceStrategy(), client, pre_extract_length=True
        )

        result = extractor.extract("secret()")

        self.assertEqual(result.value, "ab")
        self.assertTrue(result.complete)
        has_ge = any(
            ">=" in request.query["tracking"]
            and "LENGTH" in request.query["tracking"]
            for request in client.requests
        )
        self.assertTrue(has_ge, "Should use >= operator for binary search length")

    def test_pre_extract_length_zero_returns_empty(self) -> None:
        client = ConditionAwareFakeHttpClient({})
        extractor = build_extractor(
            BruteForceStrategy(), client, pre_extract_length=True
        )

        result = extractor.extract("secret()")

        self.assertEqual(result.value, "")
        self.assertTrue(result.complete)
        self.assertEqual(len(result.characters), 0)

    def test_pre_extract_skipped_on_resume(self) -> None:
        client = ConditionAwareFakeHttpClient({1: "a", 2: "b", 3: "c"})
        extractor = build_extractor(
            BruteForceStrategy(), client, pre_extract_length=True
        )
        resume = (CharacterResult(position=1, character="a", attempts=1),)

        result = extractor.extract("secret()", resume_from=resume)

        self.assertEqual(result.value, "abc")
        self.assertTrue(result.complete)
        has_ge_length = any(
            ">=" in request.query["tracking"]
            and "LENGTH" in request.query["tracking"]
            for request in client.requests
        )
        self.assertFalse(has_ge_length, "Should skip length pre-extraction on resume")


class OracleHealthCheckTests(unittest.TestCase):
    def test_health_check_runs_periodically(self) -> None:
        client = ConditionAwareFakeHttpClient({1: "a", 2: "b", 3: "c"})
        extractor = build_extractor(
            BruteForceStrategy(),
            client,
            max_length=3,
            oracle_recheck_interval=1,
        )

        result = extractor.extract("secret()")

        self.assertEqual(result.value, "abc")
        self.assertTrue(result.complete)
        health_checks = [
            r for r in client.requests
            if "1=1" in r.query["tracking"] or "1=2" in r.query["tracking"]
        ]
        self.assertGreater(len(health_checks), 0)

    def test_no_health_check_when_interval_is_zero(self) -> None:
        client = ConditionAwareFakeHttpClient({1: "a", 2: "b"})
        extractor = build_extractor(
            BruteForceStrategy(),
            client,
            oracle_recheck_interval=0,
        )

        extractor.extract("secret()")

        health_checks = [
            r for r in client.requests
            if r.query["tracking"].endswith("(1=1)-- ") or r.query["tracking"].endswith("(1=2)-- ")
        ]
        self.assertEqual(len(health_checks), 0)


class PositionRetryTests(unittest.TestCase):
    def test_retries_failed_position(self) -> None:
        call_count = {"find": 0}
        real_strategy = BruteForceStrategy()

        class FailOnceStrategy(BruteForceStrategy):
            @property
            def comparison_operator(self) -> str:
                return real_strategy.comparison_operator

            def find(self, position, charset, predicate, confirmation=None):
                call_count["find"] += 1
                if position == 1 and call_count["find"] == 1:
                    return CharacterResult(position=1, character=None, attempts=3)
                return real_strategy.find(position, charset, predicate, confirmation)

        client = ConditionAwareFakeHttpClient({1: "a", 2: "b"})
        extractor = build_extractor(
            FailOnceStrategy(),
            client,
            position_retries=2,
        )

        result = extractor.extract("secret()")

        self.assertEqual(result.characters[0].character, "a")
        self.assertTrue(call_count["find"] > 1)

    def test_no_retry_when_disabled(self) -> None:
        call_count = {"find": 0}
        real_strategy = BruteForceStrategy()

        class AlwaysFailStrategy(BruteForceStrategy):
            @property
            def comparison_operator(self) -> str:
                return real_strategy.comparison_operator

            def find(self, position, charset, predicate, confirmation=None):
                call_count["find"] += 1
                return CharacterResult(position=position, character=None, attempts=3)

        client = ConditionAwareFakeHttpClient({1: "a"})
        extractor = build_extractor(
            AlwaysFailStrategy(),
            client,
            position_retries=0,
        )

        result = extractor.extract("secret()")

        self.assertEqual(call_count["find"], 1)
        self.assertIsNone(result.characters[0].character)


if __name__ == "__main__":
    unittest.main()
