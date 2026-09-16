"""CLI parsing and error-handling tests without network access."""

import contextlib
import io
import unittest
from unittest.mock import patch

from cli.main import build_parser, main
from models import AttackResult, ExtractionResult


class CliParserTests(unittest.TestCase):
    def test_parses_repeated_values_and_request_data(self) -> None:
        args = build_parser().parse_args(
            [
                "--url",
                "https://example.test/filter",
                "--method",
                "POST",
                "--parameter",
                "tracking",
                "--location",
                "cookie",
                "--expression",
                "database()",
                "--query",
                "category=books",
                "--body",
                "search=alice",
                "--cookie",
                "session=token",
                "--header",
                "X-Test=yes",
                "--true-text",
                "Welcome back",
                "--log-file",
                "/tmp/blind-finder-test.log",
            ]
        )

        self.assertEqual(args.method, "POST")
        self.assertEqual(args.expression, ["database()"])
        self.assertEqual(args.cookie, [("session", "token")])
        self.assertEqual(args.header, [("X-Test", "yes")])

    def test_rejects_malformed_key_value(self) -> None:
        with self.assertRaises(SystemExit):
            build_parser().parse_args(
                [
                    "--url",
                    "https://example.test",
                    "--parameter",
                    "tracking",
                    "--expression",
                    "database()",
                    "--true-text",
                    "TRUE",
                    "--header",
                    "missing-separator",
                ]
            )

    def test_parses_conditional_error_options(self) -> None:
        args = build_parser().parse_args(
            [
                "--url", "https://example.test", "--parameter", "TrackingId",
                "--location", "cookie", "--expression", "password",
                "--attack-mode", "conditional-error", "--error-status", "500",
            ]
        )
        self.assertEqual(args.attack_mode, "conditional-error")
        self.assertEqual(args.error_status, 500)

    def test_parses_time_based_options(self) -> None:
        args = build_parser().parse_args(
            [
                "--url", "https://example.test", "--parameter", "tracking",
                "--technique", "time", "--dialect", "mysql",
                "--sleep-seconds", "3.5", "--timing-threshold", "2.0",
                "--timing-baseline", "0.5", "--timing-tolerance", "0.25",
            ]
        )
        self.assertEqual(args.technique, "time")
        self.assertEqual(args.dialect, "mysql")
        self.assertEqual(args.sleep_seconds, 3.5)
        self.assertEqual(args.timing_threshold, 2.0)
        self.assertEqual(args.timing_baseline, 0.5)
        self.assertEqual(args.timing_tolerance, 0.25)

    def test_uses_column_as_default_expression(self) -> None:
        args = build_parser().parse_args(
            [
                "--url", "https://example.test", "--parameter", "TrackingId",
                "--attack-mode", "conditional-error", "--error-status", "500",
                "--column", "password_hash",
            ]
        )
        self.assertIsNone(args.expression)
        self.assertEqual(args.column, "password_hash")

    def test_parses_length_status_and_transport_options(self) -> None:
        args = build_parser().parse_args(
            [
                "--url", "https://example.test", "--parameter", "tracking",
                "--detector", "length", "--expected-length", "42",
                "--allow-redirects", "--max-retries", "2", "--retry-backoff", "0.5",
            ]
        )
        self.assertEqual(args.expected_length, 42)
        self.assertTrue(args.allow_redirects)
        self.assertEqual(args.max_retries, 2)
        self.assertEqual(args.retry_backoff, 0.5)


class CliExecutionTests(unittest.TestCase):
    def _arguments(self) -> list[str]:
        return [
            "--url",
            "https://example.test/filter",
            "--parameter",
            "tracking",
            "--query",
            "tracking=base",
            "--expression",
            "database()",
            "--true-text",
            "TRUE",
        ]

    @patch("cli.main.build_attack_engine")
    def test_prints_results_and_returns_success(self, build_engine) -> None:
        build_engine.return_value.run.return_value = AttackResult(
            {"database()": ExtractionResult("database()", "abc", complete=True)}
        )
        output = io.StringIO()
        with contextlib.redirect_stdout(output):
            code = main(self._arguments())

        self.assertEqual(code, 0)
        result = output.getvalue()
        self.assertIn("SQL-IJECTOR", result)
        self.assertIn("database(): abc", result)
        build_engine.return_value.run.assert_called_once_with(["database()"])

    @patch("cli.main.build_attack_engine", side_effect=ValueError("invalid setup"))
    def test_returns_controlled_error_without_traceback(self, _build_engine) -> None:
        output = io.StringIO()
        errors = io.StringIO()
        with contextlib.redirect_stdout(output), contextlib.redirect_stderr(errors):
            code = main(self._arguments())

        self.assertEqual(code, 2)
        self.assertIn("SQL-IJECTOR", output.getvalue())

    @patch("cli.main.build_attack_engine")
    def test_marks_incomplete_extraction(self, build_engine) -> None:
        build_engine.return_value.run.return_value = AttackResult(
            {"database()": ExtractionResult("database()", "ab", complete=False)}
        )
        output = io.StringIO()
        with contextlib.redirect_stdout(output):
            code = main(self._arguments())

        self.assertEqual(code, 0)
        self.assertIn("SQL-IJECTOR", output.getvalue())
        self.assertIn("extraction incomplete", output.getvalue())

    @patch("cli.main.build_attack_engine", side_effect=ValueError("invalid setup"))
    @patch("cli.main.configure_logging")
    def test_configures_custom_log_file(self, configure, _build_engine) -> None:
        main(self._arguments() + ["--log-file", "/tmp/custom.log"])

        configure.assert_called_once()
        self.assertEqual(configure.call_args.kwargs["log_file"].as_posix(), "/tmp/custom.log")

    @patch("cli.main.build_attack_engine", side_effect=KeyboardInterrupt)
    def test_handles_user_interrupt_without_traceback(self, _build_engine) -> None:
        with contextlib.redirect_stdout(io.StringIO()):
            code = main(self._arguments())

        self.assertEqual(code, 130)


if __name__ == "__main__":
    unittest.main()
