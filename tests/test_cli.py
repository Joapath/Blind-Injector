"""CLI parsing and error-handling tests without network access."""

import contextlib
import io
import json
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from cli.main import build_parser, main
from core.checkpoint import CheckpointStore, compute_session_id
from core.fingerprint import FingerprintResult
from models import AttackConfiguration, AttackResult, CharacterResult, ExtractionResult, Target


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

    def test_parses_waf_evasion_options(self) -> None:
        args = build_parser().parse_args(
            [
                "--url", "https://example.test", "--parameter", "tracking",
                "--tamper", "space2comment,randomcase",
                "--tamper-profile", "cloudflare",
                "--random-agent", "--random-xff",
            ]
        )
        self.assertEqual(args.tamper, ["space2comment", "randomcase"])
        self.assertEqual(args.tamper_profile, "cloudflare")
        self.assertTrue(args.random_agent)
        self.assertTrue(args.random_xff)

    def test_rejects_unknown_tamper_profile(self) -> None:
        with self.assertRaises(SystemExit):
            build_parser().parse_args(
                [
                    "--url", "https://example.test", "--parameter", "tracking",
                    "--tamper-profile", "not-a-real-profile",
                ]
            )

    def test_technique_accepts_auto(self) -> None:
        args = build_parser().parse_args(
            [
                "--url", "https://example.test", "--parameter", "tracking",
                "--technique", "auto",
            ]
        )
        self.assertEqual(args.technique, "auto")

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
        self.assertIn("Blind-Injector", result)
        self.assertIn("database()", result)
        self.assertIn("abc", result)
        build_engine.return_value.run.assert_called_once_with(["database()"], resume={})

    @patch("cli.main.build_attack_engine", side_effect=ValueError("invalid setup"))
    def test_returns_controlled_error_without_traceback(self, _build_engine) -> None:
        output = io.StringIO()
        errors = io.StringIO()
        with contextlib.redirect_stdout(output), contextlib.redirect_stderr(errors):
            code = main(self._arguments())

        self.assertEqual(code, 2)
        self.assertIn("Blind-Injector", output.getvalue())

    @patch("cli.main.build_attack_engine")
    def test_marks_incomplete_extraction(self, build_engine) -> None:
        build_engine.return_value.run.return_value = AttackResult(
            {"database()": ExtractionResult("database()", "ab", complete=False)}
        )
        output = io.StringIO()
        with contextlib.redirect_stdout(output):
            code = main(self._arguments())

        self.assertEqual(code, 0)
        self.assertIn("Blind-Injector", output.getvalue())
        self.assertIn("incomplete", output.getvalue())

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

    @patch("cli.main.build_attack_engine")
    def test_report_file_is_written_on_success(self, build_engine) -> None:
        build_engine.return_value.run.return_value = AttackResult(
            {"database()": ExtractionResult("database()", "abc", complete=True)}
        )
        with tempfile.TemporaryDirectory() as tmp:
            report_path = Path(tmp) / "report.json"
            with contextlib.redirect_stdout(io.StringIO()):
                code = main(self._arguments() + ["--report-file", str(report_path)])

            self.assertEqual(code, 0)
            self.assertTrue(report_path.exists())
            report = json.loads(report_path.read_text(encoding="utf-8"))
            self.assertEqual(report["extractions"][0]["value"], "abc")

    @patch("cli.main.build_attack_engine")
    def test_report_file_is_not_written_on_interrupt(self, build_engine) -> None:
        build_engine.return_value.run.side_effect = KeyboardInterrupt
        with tempfile.TemporaryDirectory() as tmp:
            report_path = Path(tmp) / "report.json"
            with contextlib.redirect_stdout(io.StringIO()):
                main(self._arguments() + ["--report-file", str(report_path)])

            self.assertFalse(report_path.exists())

    @patch("cli.main.build_attack_engine", side_effect=ValueError("invalid setup"))
    def test_rejects_unsupported_report_format(self, _build_engine) -> None:
        with self.assertRaises(SystemExit):
            build_parser().parse_args(
                self._arguments() + ["--report-format", "xml"]
            )


class CliCheckpointTests(unittest.TestCase):
    """End-to-end checkpoint/resume wiring, with build_attack_engine mocked
    (no network) but the real CheckpointStore/compute_session_id."""

    def _arguments(self, checkpoint_dir: str, extra: list[str] | None = None) -> list[str]:
        return [
            "--url", "https://example.test/filter",
            "--parameter", "tracking",
            "--query", "tracking=base",
            "--expression", "database()",
            "--true-text", "TRUE",
            "--checkpoint-dir", checkpoint_dir,
        ] + (extra or [])

    def _matching_configuration(self, checkpoint_dir: str) -> AttackConfiguration:
        # Must mirror exactly what main() builds from _arguments() above,
        # since compute_session_id hashes the whole configuration.
        return AttackConfiguration(
            target=Target("https://example.test/filter", query={"tracking": "base"}),
            parameter="tracking",
            detector_value="TRUE",
            checkpoint_dir=checkpoint_dir,
        )

    @patch("cli.main.build_attack_engine")
    def test_resume_loads_checkpoint_and_forwards_resume_map(self, build_engine) -> None:
        build_engine.return_value.run.return_value = AttackResult(
            {"database()": ExtractionResult("database()", "abc", complete=True)}
        )
        with tempfile.TemporaryDirectory() as tmp:
            session_id = compute_session_id(self._matching_configuration(tmp), ["database()"])
            saved = (CharacterResult(1, "a", attempts=2),)
            CheckpointStore(Path(tmp)).save(session_id, "database()", saved, complete=False)

            with contextlib.redirect_stdout(io.StringIO()):
                main(self._arguments(tmp, ["--resume"]))

            _, kwargs = build_engine.return_value.run.call_args
            self.assertEqual(kwargs["resume"], {"database()": saved})

    @patch("cli.main.build_attack_engine")
    def test_without_resume_flag_ignores_an_existing_checkpoint(self, build_engine) -> None:
        build_engine.return_value.run.return_value = AttackResult(
            {"database()": ExtractionResult("database()", "abc", complete=True)}
        )
        with tempfile.TemporaryDirectory() as tmp:
            session_id = compute_session_id(self._matching_configuration(tmp), ["database()"])
            CheckpointStore(Path(tmp)).save(
                session_id, "database()", (CharacterResult(1, "a"),), complete=False
            )

            with contextlib.redirect_stdout(io.StringIO()):
                main(self._arguments(tmp))  # no --resume

            _, kwargs = build_engine.return_value.run.call_args
            self.assertEqual(kwargs["resume"], {})

    @patch("cli.main.build_attack_engine")
    def test_successful_completion_clears_the_checkpoint(self, build_engine) -> None:
        build_engine.return_value.run.return_value = AttackResult(
            {"database()": ExtractionResult("database()", "abc", complete=True)}
        )
        with tempfile.TemporaryDirectory() as tmp:
            store = CheckpointStore(Path(tmp))
            session_id = compute_session_id(self._matching_configuration(tmp), ["database()"])
            store.save(session_id, "database()", (CharacterResult(1, "a"),), complete=False)

            with contextlib.redirect_stdout(io.StringIO()):
                code = main(self._arguments(tmp))

            self.assertEqual(code, 0)
            self.assertIsNone(store.load(session_id))

    @patch("cli.main.build_attack_engine")
    def test_incomplete_result_keeps_the_checkpoint(self, build_engine) -> None:
        build_engine.return_value.run.return_value = AttackResult(
            {"database()": ExtractionResult("database()", "ab", complete=False)}
        )
        with tempfile.TemporaryDirectory() as tmp:
            store = CheckpointStore(Path(tmp))
            session_id = compute_session_id(self._matching_configuration(tmp), ["database()"])
            store.save(session_id, "database()", (CharacterResult(1, "a"),), complete=False)

            with contextlib.redirect_stdout(io.StringIO()):
                main(self._arguments(tmp))

            self.assertIsNotNone(store.load(session_id))


class CliFingerprintTests(unittest.TestCase):
    def _arguments(self) -> list[str]:
        return [
            "--url", "https://example.test/filter",
            "--parameter", "tracking",
            "--query", "tracking=base",
            "--expression", "database()",
            "--technique", "auto",
        ]

    @patch("cli.main.build_attack_engine")
    @patch("cli.main.fingerprint")
    def test_confirmed_fingerprint_replaces_configuration_before_building(
        self, fingerprint_mock, build_engine
    ) -> None:
        fingerprint_mock.return_value = FingerprintResult(
            technique="boolean",
            detector="status",
            attack_mode="conditional-response",
            expected_status=200,
            confidence="confirmed",
        )
        build_engine.return_value.run.return_value = AttackResult(
            {"database()": ExtractionResult("database()", "abc", complete=True)}
        )

        with contextlib.redirect_stdout(io.StringIO()) as output:
            code = main(self._arguments())

        self.assertEqual(code, 0)
        self.assertIn("confidence=confirmed", output.getvalue())
        used_configuration = build_engine.call_args.args[0]
        self.assertEqual(used_configuration.technique, "boolean")
        self.assertEqual(used_configuration.detector, "status")
        self.assertEqual(used_configuration.expected_status, 200)

    @patch("cli.main.build_attack_engine")
    @patch("cli.main.fingerprint")
    def test_no_confidence_fails_without_guessing(self, fingerprint_mock, build_engine) -> None:
        fingerprint_mock.return_value = FingerprintResult(
            confidence="none", notes=("no distinguishable oracle found",)
        )

        with contextlib.redirect_stdout(io.StringIO()) as output:
            code = main(self._arguments())

        self.assertEqual(code, 2)
        self.assertIn("no distinguishable oracle found", output.getvalue())
        build_engine.assert_not_called()


class CliProbeAllTests(unittest.TestCase):
    def _arguments(self) -> list[str]:
        return [
            "--url", "https://example.test/filter",
            "--query", "category=Gifts", "--cookie", "TrackingId=abc",
            "--technique", "auto", "--expression", "database()",
        ]

    @patch("cli.main.build_attack_engine")
    @patch("cli.main.fingerprint")
    def test_probes_candidates_and_selects_first_with_oracle(
        self, fingerprint_mock, build_engine
    ) -> None:
        # category (query) has no oracle; TrackingId (cookie) does.
        def fake_fingerprint(config):
            if config.parameter == "TrackingId":
                return FingerprintResult(
                    technique="boolean", detector="text", attack_mode="conditional-response",
                    detector_value="Welcome", dialect="postgres", confidence="confirmed",
                )
            return FingerprintResult(confidence="none")

        fingerprint_mock.side_effect = fake_fingerprint
        build_engine.return_value.run.return_value = AttackResult(
            {"database()": ExtractionResult("database()", "x", complete=True)}
        )

        with contextlib.redirect_stdout(io.StringIO()) as output:
            code = main(self._arguments())

        self.assertEqual(code, 0)
        text = output.getvalue()
        self.assertIn("parameter=category location=query", text)
        self.assertIn("no oracle", text)
        self.assertIn("parameter=TrackingId location=cookie", text)
        self.assertIn("boolean/text", text)
        used_configuration = build_engine.call_args.args[0]
        self.assertEqual(used_configuration.parameter, "TrackingId")
        self.assertEqual(used_configuration.injection_location, "cookie")
        self.assertEqual(used_configuration.dialect, "postgres")

    @patch("cli.main.build_attack_engine")
    @patch("cli.main.fingerprint")
    def test_no_candidate_with_oracle_fails(self, fingerprint_mock, build_engine) -> None:
        fingerprint_mock.return_value = FingerprintResult(confidence="none")

        errors = io.StringIO()
        with contextlib.redirect_stdout(io.StringIO()), contextlib.redirect_stderr(errors):
            code = main(self._arguments())

        self.assertEqual(code, 2)
        self.assertIn("no injectable parameter found among", errors.getvalue())
        build_engine.assert_not_called()

    def test_no_parameter_without_auto_errors(self) -> None:
        with contextlib.redirect_stderr(io.StringIO()):
            with self.assertRaises(SystemExit):
                main([
                    "--url", "https://example.test/filter",
                    "--query", "category=Gifts", "--expression", "database()",
                ])


class CliRequestFileTests(unittest.TestCase):
    def _write_request(self, tmp_dir: str, text: str) -> str:
        path = Path(tmp_dir) / "request.txt"
        path.write_text(text, encoding="utf-8")
        return str(path)

    @patch("cli.main.build_attack_engine")
    def test_request_file_auto_detects_injection_point(self, build_engine) -> None:
        build_engine.return_value.run.return_value = AttackResult(
            {"database()": ExtractionResult("database()", "abc", complete=True)}
        )
        with tempfile.TemporaryDirectory() as tmp:
            request_path = self._write_request(
                tmp,
                "GET /filter?category=Gifts HTTP/2\r\n"
                "Host: example.test\r\n"
                "Cookie: TrackingId=abc123*; session=xyz\r\n"
                "\r\n",
            )
            output = io.StringIO()
            with contextlib.redirect_stdout(output):
                code = main(
                    [
                        "--request-file", request_path,
                        "--expression", "database()",
                        "--true-text", "TRUE",
                    ]
                )

        self.assertEqual(code, 0)
        text = output.getvalue()
        self.assertIn("auto-detected injection point", text)
        self.assertIn("parameter=TrackingId", text)
        self.assertIn("location=cookie", text)
        used_configuration = build_engine.call_args.args[0]
        self.assertEqual(used_configuration.parameter, "TrackingId")
        self.assertEqual(used_configuration.injection_location, "cookie")
        self.assertEqual(used_configuration.target.url, "http://example.test/filter")
        self.assertEqual(used_configuration.target.cookies["TrackingId"], "abc123")

    @patch("cli.main.build_attack_engine")
    def test_request_file_without_marker_requires_explicit_parameter(self, build_engine) -> None:
        build_engine.return_value.run.return_value = AttackResult(
            {"database()": ExtractionResult("database()", "abc", complete=True)}
        )
        with tempfile.TemporaryDirectory() as tmp:
            request_path = self._write_request(
                tmp,
                "GET /filter?category=Gifts HTTP/2\r\n"
                "Host: example.test\r\n"
                "Cookie: TrackingId=abc123; session=xyz\r\n"
                "\r\n",
            )
            with contextlib.redirect_stdout(io.StringIO()), contextlib.redirect_stderr(io.StringIO()):
                with self.assertRaises(SystemExit):
                    main(
                        ["--request-file", request_path, "--expression", "database()", "--true-text", "TRUE"]
                    )
                code_with_parameter = main(
                    [
                        "--request-file", request_path,
                        "--parameter", "TrackingId", "--location", "cookie",
                        "--expression", "database()", "--true-text", "TRUE",
                    ]
                )

        self.assertEqual(code_with_parameter, 0)
        used_configuration = build_engine.call_args.args[0]
        self.assertEqual(used_configuration.parameter, "TrackingId")

    def test_request_file_rejects_url_combination(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            request_path = self._write_request(
                tmp, "GET / HTTP/1.1\r\nHost: example.test\r\n\r\n"
            )
            with contextlib.redirect_stderr(io.StringIO()):
                with self.assertRaises(SystemExit):
                    main(["--request-file", request_path, "--url", "https://example.test"])

    def test_request_file_rejects_manual_request_flags(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            request_path = self._write_request(
                tmp, "GET / HTTP/1.1\r\nHost: example.test\r\n\r\n"
            )
            with contextlib.redirect_stderr(io.StringIO()):
                with self.assertRaises(SystemExit):
                    main(["--request-file", request_path, "--cookie", "a=b"])

    def test_requires_url_or_request_file(self) -> None:
        with contextlib.redirect_stderr(io.StringIO()):
            with self.assertRaises(SystemExit):
                main(["--parameter", "tracking", "--expression", "database()", "--true-text", "TRUE"])


class CliEnumTests(unittest.TestCase):
    def _base(self) -> list[str]:
        return [
            "--url", "https://example.test/filter",
            "--parameter", "tracking", "--query", "tracking=base",
            "--true-text", "TRUE", "--dialect", "mysql",
        ]

    @patch("cli.main.build_attack_engine")
    def test_enum_builds_and_runs_canned_expression(self, build_engine) -> None:
        expression = "(SELECT VERSION())"
        build_engine.return_value.run.return_value = AttackResult(
            {expression: ExtractionResult(expression, "8.0", complete=True)}
        )
        output = io.StringIO()
        with contextlib.redirect_stdout(output):
            code = main(self._base() + ["--enum", "version"])

        self.assertEqual(code, 0)
        self.assertIn("[enum] version:", output.getvalue())
        build_engine.return_value.run.assert_called_once_with([expression], resume={})

    @patch("cli.main.build_attack_engine")
    def test_enum_columns_uses_table(self, build_engine) -> None:
        build_engine.return_value.run.return_value = AttackResult({})
        output = io.StringIO()
        with contextlib.redirect_stdout(output):
            code = main(self._base() + ["--enum", "columns", "--table", "users"])

        self.assertEqual(code, 0)
        requested = build_engine.return_value.run.call_args.args[0]
        self.assertEqual(len(requested), 1)
        self.assertIn("table_name='users'", requested[0])

    @patch("cli.main.build_attack_engine")
    def test_enum_combines_with_explicit_expression(self, build_engine) -> None:
        build_engine.return_value.run.return_value = AttackResult({})
        with contextlib.redirect_stdout(io.StringIO()):
            code = main(self._base() + ["--expression", "database()", "--enum", "version"])

        self.assertEqual(code, 0)
        requested = build_engine.return_value.run.call_args.args[0]
        self.assertEqual(requested, ["database()", "(SELECT VERSION())"])

    @patch("cli.main.build_attack_engine")
    def test_enum_list_kind_extends_charset(self, build_engine) -> None:
        build_engine.return_value.run.return_value = AttackResult({})
        output = io.StringIO()
        with contextlib.redirect_stdout(output):
            code = main(self._base() + ["--enum", "tables"])

        self.assertEqual(code, 0)
        self.assertIn("[enum] extended charset", output.getvalue())
        used_configuration = build_engine.call_args.args[0]
        self.assertIn(",", used_configuration.charset)
        self.assertIn("_", used_configuration.charset)

    @patch("cli.main.build_attack_engine")
    def test_enum_scalar_kind_does_not_extend_charset(self, build_engine) -> None:
        build_engine.return_value.run.return_value = AttackResult({})
        output = io.StringIO()
        with contextlib.redirect_stdout(output):
            code = main(self._base() + ["--enum", "version"])

        self.assertEqual(code, 0)
        self.assertNotIn("extended charset", output.getvalue())
        used_configuration = build_engine.call_args.args[0]
        self.assertNotIn(",", used_configuration.charset)

    @patch("cli.main.build_attack_engine")
    def test_enum_does_not_override_explicit_charset(self, build_engine) -> None:
        build_engine.return_value.run.return_value = AttackResult({})
        with contextlib.redirect_stdout(io.StringIO()):
            code = main(self._base() + ["--enum", "tables", "--charset", "abc,"])

        self.assertEqual(code, 0)
        used_configuration = build_engine.call_args.args[0]
        self.assertEqual(used_configuration.charset, "abc,")

    @patch("cli.main.build_attack_engine")
    @patch("cli.main.fingerprint")
    def test_enum_without_known_dialect_fails(self, fingerprint_mock, build_engine) -> None:
        # Auto fingerprint finds a boolean oracle but no dialect; --enum must not
        # silently fall back to the default dialect.
        fingerprint_mock.return_value = FingerprintResult(
            technique="boolean", detector="text", attack_mode="conditional-response",
            detector_value="Welcome", dialect=None, confidence="confirmed",
        )
        errors = io.StringIO()
        with contextlib.redirect_stdout(io.StringIO()), contextlib.redirect_stderr(errors):
            code = main([
                "--url", "https://example.test/filter", "--parameter", "tracking",
                "--query", "tracking=base", "--technique", "auto", "--enum", "tables",
            ])

        self.assertEqual(code, 2)
        self.assertIn("--enum needs a known database dialect", errors.getvalue())
        build_engine.assert_not_called()

    @patch("cli.main.build_attack_engine")
    def test_enum_columns_falls_back_to_default_table(self, build_engine) -> None:
        build_engine.return_value.run.return_value = AttackResult({})
        output = io.StringIO()
        with contextlib.redirect_stdout(output):
            code = main(self._base() + ["--enum", "columns"])

        self.assertEqual(code, 0)
        requested = build_engine.return_value.run.call_args.args[0]
        self.assertIn("table_name='users'", requested[0])
        self.assertIn("[enum] columns:", output.getvalue())


class CliShortcutTests(unittest.TestCase):
    """Tests for sqlmap-style enumeration shortcuts (Paso 2, Fase 2)."""

    def _base(self, dialect: str = "mysql") -> list[str]:
        return [
            "--url", "https://example.test/filter",
            "--parameter", "tracking", "--query", "tracking=base",
            "--true-text", "TRUE", "--dialect", dialect,
        ]

    @patch("cli.main.build_attack_engine")
    def test_dbs_shortcut(self, build_engine) -> None:
        build_engine.return_value.run.return_value = AttackResult({})
        output = io.StringIO()
        with contextlib.redirect_stdout(output):
            code = main(self._base() + ["--dbs"])

        self.assertEqual(code, 0)
        requested = build_engine.return_value.run.call_args.args[0]
        self.assertEqual(len(requested), 1)
        self.assertIn("schema_name", requested[0])

    @patch("cli.main.build_attack_engine")
    def test_tables_shortcut(self, build_engine) -> None:
        build_engine.return_value.run.return_value = AttackResult({})
        output = io.StringIO()
        with contextlib.redirect_stdout(output):
            code = main(self._base() + ["--tables"])

        self.assertEqual(code, 0)
        requested = build_engine.return_value.run.call_args.args[0]
        self.assertIn("table_name", requested[0])

    @patch("cli.main.build_attack_engine")
    def test_list_columns_shortcut(self, build_engine) -> None:
        build_engine.return_value.run.return_value = AttackResult({})
        output = io.StringIO()
        with contextlib.redirect_stdout(output):
            code = main(self._base() + ["--list-columns", "-T", "products"])

        self.assertEqual(code, 0)
        requested = build_engine.return_value.run.call_args.args[0]
        self.assertIn("column_name", requested[0])
        self.assertIn("table_name='products'", requested[0])

    @patch("cli.main.build_attack_engine")
    def test_count_shortcut(self, build_engine) -> None:
        build_engine.return_value.run.return_value = AttackResult({})
        output = io.StringIO()
        with contextlib.redirect_stdout(output):
            code = main(self._base() + ["--count", "-T", "orders"])

        self.assertEqual(code, 0)
        requested = build_engine.return_value.run.call_args.args[0]
        self.assertIn("COUNT(*)", requested[0])
        self.assertIn("orders", requested[0])

    @patch("cli.main.build_attack_engine")
    def test_current_db_shortcut(self, build_engine) -> None:
        build_engine.return_value.run.return_value = AttackResult({})
        output = io.StringIO()
        with contextlib.redirect_stdout(output):
            code = main(self._base() + ["--current-db"])

        self.assertEqual(code, 0)
        requested = build_engine.return_value.run.call_args.args[0]
        self.assertIn("DATABASE()", requested[0])

    @patch("cli.main.build_attack_engine")
    def test_current_user_shortcut(self, build_engine) -> None:
        build_engine.return_value.run.return_value = AttackResult({})
        output = io.StringIO()
        with contextlib.redirect_stdout(output):
            code = main(self._base() + ["--current-user"])

        self.assertEqual(code, 0)
        requested = build_engine.return_value.run.call_args.args[0]
        self.assertIn("CURRENT_USER()", requested[0])

    @patch("cli.main.build_attack_engine")
    def test_tables_with_database_scope(self, build_engine) -> None:
        build_engine.return_value.run.return_value = AttackResult({})
        output = io.StringIO()
        with contextlib.redirect_stdout(output):
            code = main(self._base() + ["--tables", "-D", "mydb"])

        self.assertEqual(code, 0)
        requested = build_engine.return_value.run.call_args.args[0]
        self.assertIn("'mydb'", requested[0])
        self.assertNotIn("DATABASE()", requested[0])

    @patch("cli.main.build_attack_engine")
    def test_list_columns_with_database_scope(self, build_engine) -> None:
        build_engine.return_value.run.return_value = AttackResult({})
        with contextlib.redirect_stdout(io.StringIO()):
            code = main(self._base() + ["--list-columns", "-T", "users", "-D", "shop"])

        self.assertEqual(code, 0)
        requested = build_engine.return_value.run.call_args.args[0]
        self.assertIn("table_schema='shop'", requested[0])

    def test_mutual_exclusion(self) -> None:
        with self.assertRaises(SystemExit):
            build_parser().parse_args(
                self._base() + ["--dbs", "--tables"]
            )

    @patch("cli.main.build_attack_engine")
    def test_shortcut_coexists_with_expression(self, build_engine) -> None:
        build_engine.return_value.run.return_value = AttackResult({})
        with contextlib.redirect_stdout(io.StringIO()):
            code = main(self._base() + ["--dbs", "--expression", "VERSION()"])

        self.assertEqual(code, 0)
        requested = build_engine.return_value.run.call_args.args[0]
        self.assertEqual(len(requested), 2)
        self.assertEqual(requested[0], "VERSION()")
        self.assertIn("schema_name", requested[1])

    @patch("cli.main.build_attack_engine")
    def test_t_alias_works(self, build_engine) -> None:
        build_engine.return_value.run.return_value = AttackResult({})
        with contextlib.redirect_stdout(io.StringIO()):
            code = main(self._base() + ["--count", "-T", "products"])

        self.assertEqual(code, 0)
        requested = build_engine.return_value.run.call_args.args[0]
        self.assertIn("products", requested[0])

    @patch("cli.main.build_attack_engine")
    def test_dbs_extends_charset(self, build_engine) -> None:
        build_engine.return_value.run.return_value = AttackResult({})
        with contextlib.redirect_stdout(io.StringIO()):
            code = main(self._base() + ["--dbs"])

        self.assertEqual(code, 0)
        used_config = build_engine.call_args.args[0]
        self.assertIn(",", used_config.charset)
        self.assertIn("_", used_config.charset)

    @patch("cli.main.build_attack_engine")
    def test_current_db_does_not_extend_charset(self, build_engine) -> None:
        build_engine.return_value.run.return_value = AttackResult({})
        with contextlib.redirect_stdout(io.StringIO()):
            code = main(self._base() + ["--current-db"])

        self.assertEqual(code, 0)
        used_config = build_engine.call_args.args[0]
        self.assertNotIn(",", used_config.charset)

    def test_dump_columns_parsed_as_list(self) -> None:
        args = build_parser().parse_args(
            self._base() + ["--dump", "-C", "user,pass,email"]
        )
        self.assertEqual(args.dump_columns, ["user", "pass", "email"])

    def test_dump_limit_default(self) -> None:
        args = build_parser().parse_args(self._base() + ["--dump"])
        self.assertEqual(args.dump_limit, 10)

    def test_dump_limit_custom(self) -> None:
        args = build_parser().parse_args(
            self._base() + ["--dump", "--dump-limit", "50"]
        )
        self.assertEqual(args.dump_limit, 50)

    @patch("cli.main.build_attack_engine")
    def test_tables_oracle_dialect(self, build_engine) -> None:
        build_engine.return_value.run.return_value = AttackResult({})
        with contextlib.redirect_stdout(io.StringIO()):
            code = main(self._base("oracle") + ["--tables"])

        self.assertEqual(code, 0)
        requested = build_engine.return_value.run.call_args.args[0]
        self.assertIn("LISTAGG", requested[0])
        self.assertIn("all_tables", requested[0])


class CliDumpTests(unittest.TestCase):
    """Tests for --dump multi-step flow (Paso 4, Fase 2)."""

    def _base(self, dialect: str = "mysql") -> list[str]:
        return [
            "--url", "https://example.test/filter",
            "--parameter", "tracking", "--query", "tracking=base",
            "--true-text", "TRUE", "--dialect", dialect,
        ]

    @patch("cli.main.build_attack_engine")
    def test_dump_full_flow(self, build_engine) -> None:
        """3-step dump: columns → count → rows."""
        from cli.enum_catalog import ROW_SEPARATOR

        def fake_run(expressions, resume=None):
            expr0 = expressions[0]
            if "column_name" in expr0:
                return AttackResult(
                    {expr0: ExtractionResult(expr0, "id,name,email", complete=True)}
                )
            if "COUNT" in expr0:
                return AttackResult(
                    {expr0: ExtractionResult(expr0, "2", complete=True)}
                )
            return AttackResult({
                e: ExtractionResult(
                    e, ROW_SEPARATOR.join([f"v{i}", f"n{i}", f"e{i}"]), complete=True
                )
                for i, e in enumerate(expressions)
            })

        build_engine.return_value.run.side_effect = fake_run
        output = io.StringIO()
        with contextlib.redirect_stdout(output):
            code = main(self._base() + ["--dump", "-T", "users", "--dump-limit", "5"])

        self.assertEqual(code, 0)
        text = output.getvalue()
        self.assertIn("[dump] step 1/3", text)
        self.assertIn("[dump] step 2/3", text)
        self.assertIn("[dump] step 3/3", text)
        self.assertIn("columns: id,name,email", text)
        self.assertIn("rows: 2", text)
        self.assertIn("v0", text)
        self.assertIn("v1", text)
        self.assertEqual(build_engine.return_value.run.call_count, 3)

    @patch("cli.main.build_attack_engine")
    def test_dump_with_specified_columns_skips_step1(self, build_engine) -> None:
        from cli.enum_catalog import ROW_SEPARATOR

        def fake_run(expressions, resume=None):
            expr0 = expressions[0]
            if "COUNT" in expr0:
                return AttackResult(
                    {expr0: ExtractionResult(expr0, "1", complete=True)}
                )
            return AttackResult({
                e: ExtractionResult(e, ROW_SEPARATOR.join(["admin", "s3cret"]), complete=True)
                for e in expressions
            })

        build_engine.return_value.run.side_effect = fake_run
        output = io.StringIO()
        with contextlib.redirect_stdout(output):
            code = main(
                self._base() + ["--dump", "-T", "users", "-C", "name,pass"]
            )

        self.assertEqual(code, 0)
        text = output.getvalue()
        self.assertIn("using specified columns: name,pass", text)
        self.assertIn("admin", text)
        self.assertIn("s3cret", text)
        self.assertEqual(build_engine.return_value.run.call_count, 2)

    @patch("cli.main.build_attack_engine")
    def test_dump_limit_caps_rows(self, build_engine) -> None:
        from cli.enum_catalog import ROW_SEPARATOR

        def fake_run(expressions, resume=None):
            expr0 = expressions[0]
            if "COUNT" in expr0:
                return AttackResult(
                    {expr0: ExtractionResult(expr0, "100", complete=True)}
                )
            return AttackResult({
                e: ExtractionResult(e, "x", complete=True)
                for e in expressions
            })

        build_engine.return_value.run.side_effect = fake_run
        output = io.StringIO()
        with contextlib.redirect_stdout(output):
            code = main(
                self._base() + ["--dump", "-T", "users", "-C", "id", "--dump-limit", "3"]
            )

        self.assertEqual(code, 0)
        text = output.getvalue()
        self.assertIn("3/100 rows", text)
        last_run_args = build_engine.return_value.run.call_args.args[0]
        self.assertEqual(len(last_run_args), 3)

    @patch("cli.main.build_attack_engine")
    def test_dump_empty_table(self, build_engine) -> None:
        def fake_run(expressions, resume=None):
            expr0 = expressions[0]
            if "column_name" in expr0:
                return AttackResult(
                    {expr0: ExtractionResult(expr0, "id", complete=True)}
                )
            return AttackResult(
                {expr0: ExtractionResult(expr0, "0", complete=True)}
            )

        build_engine.return_value.run.side_effect = fake_run
        output = io.StringIO()
        with contextlib.redirect_stdout(output):
            code = main(self._base() + ["--dump", "-T", "empty_table"])

        self.assertEqual(code, 0)
        self.assertIn("empty", output.getvalue())
        self.assertEqual(build_engine.return_value.run.call_count, 2)

    @patch("cli.main.build_attack_engine")
    @patch("cli.main.fingerprint")
    def test_dump_requires_dialect(self, fingerprint_mock, build_engine) -> None:
        fingerprint_mock.return_value = FingerprintResult(
            technique="boolean", detector="text", attack_mode="conditional-response",
            detector_value="Welcome", dialect=None, confidence="confirmed",
        )
        errors = io.StringIO()
        with contextlib.redirect_stdout(io.StringIO()), contextlib.redirect_stderr(errors):
            code = main([
                "--url", "https://example.test/filter", "--parameter", "tracking",
                "--query", "tracking=base", "--technique", "auto", "--dump", "-T", "users",
            ])

        self.assertEqual(code, 2)
        self.assertIn("dialect", errors.getvalue())
        build_engine.return_value.run.assert_not_called()

    @patch("cli.main.build_attack_engine")
    def test_dump_extends_charset_for_rows(self, build_engine) -> None:
        from cli.enum_catalog import DUMP_EXTRA_CHARS, ROW_SEPARATOR

        def fake_run(expressions, resume=None):
            expr0 = expressions[0]
            if "COUNT" in expr0:
                return AttackResult(
                    {expr0: ExtractionResult(expr0, "1", complete=True)}
                )
            return AttackResult({
                e: ExtractionResult(e, "val", complete=True)
                for e in expressions
            })

        build_engine.return_value.run.side_effect = fake_run
        with contextlib.redirect_stdout(io.StringIO()):
            code = main(
                self._base() + ["--dump", "-T", "users", "-C", "id"]
            )

        self.assertEqual(code, 0)
        last_config = build_engine.call_args_list[-1].args[0]
        self.assertIn(ROW_SEPARATOR, last_config.charset)
        for c in "ABC":
            self.assertIn(c, last_config.charset)


if __name__ == "__main__":
    unittest.main()
