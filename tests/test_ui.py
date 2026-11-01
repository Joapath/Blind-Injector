"""Tests for the ui module."""

import io
import unittest

from rich.console import Console

from models.attack import AttackResult, CharacterResult, ExtractionResult
from ui.console import (
    ExtractionProgress,
    banner,
    config_summary,
    error,
    info,
    metrics_summary,
    result_table,
    success,
    warning,
)


class _CaptureBase(unittest.TestCase):
    """Mixin that patches ui.console.console to capture output."""

    def setUp(self) -> None:
        import ui.console as mod

        self._buf = io.StringIO()
        self._original = mod.console
        mod.console = Console(file=self._buf, highlight=False, width=120)

    def tearDown(self) -> None:
        import ui.console as mod

        mod.console = self._original

    @property
    def output(self) -> str:
        return self._buf.getvalue()


class BannerTests(_CaptureBase):
    def test_banner_contains_name(self) -> None:
        banner()
        self.assertIn("Blind-Injector", self.output)
        self.assertIn("Joapath", self.output)


class LeveledMessageTests(_CaptureBase):
    def test_info_default_prefix(self) -> None:
        info("hello")
        self.assertIn("[*]", self.output)
        self.assertIn("hello", self.output)

    def test_info_custom_prefix(self) -> None:
        info("testing", prefix="probe")
        self.assertIn("[probe]", self.output)

    def test_success(self) -> None:
        success("done")
        self.assertIn("[+]", self.output)
        self.assertIn("done", self.output)

    def test_warning(self) -> None:
        warning("careful")
        self.assertIn("[!]", self.output)

    def test_error(self) -> None:
        error("broken")
        self.assertIn("broken", self.output)


class ResultTableTests(_CaptureBase):
    def test_shows_expression_and_value(self) -> None:
        results = AttackResult(
            {
                "password": ExtractionResult(
                    "password",
                    "abc123",
                    characters=(
                        CharacterResult(1, "a", 5),
                        CharacterResult(2, "b", 5),
                        CharacterResult(3, "c", 5),
                    ),
                    complete=True,
                ),
            }
        )
        result_table(results)
        self.assertIn("password", self.output)
        self.assertIn("abc123", self.output)

    def test_shows_incomplete(self) -> None:
        results = AttackResult(
            {"expr": ExtractionResult("expr", "ab", complete=False)}
        )
        result_table(results)
        self.assertIn("incomplete", self.output)


class MetricsSummaryTests(_CaptureBase):
    def test_shows_duration_and_requests(self) -> None:
        metrics_summary(120.5, 200, 2)
        self.assertIn("2m", self.output)
        self.assertIn("200 requests", self.output)

    def test_short_duration(self) -> None:
        metrics_summary(5.3, 10, 1)
        self.assertIn("5.3s", self.output)


class ExtractionProgressTests(unittest.TestCase):
    def test_tracker_lifecycle(self) -> None:
        tracker = ExtractionProgress(["expr1"], max_length=10)
        tracker.start()
        tracker.update(
            "expr1",
            (CharacterResult(1, "a", 3),),
            False,
        )
        tracker.update(
            "expr1",
            (CharacterResult(1, "a", 3), CharacterResult(2, "b", 2)),
            True,
        )
        tracker.stop()

    def test_unknown_expression_ignored(self) -> None:
        tracker = ExtractionProgress(["expr1"], max_length=5)
        tracker.start()
        tracker.update("unknown", (CharacterResult(1, "x", 1),), False)
        tracker.stop()


class ConfigSummaryTests(_CaptureBase):
    def test_shows_target_and_technique(self) -> None:
        from models.target import AttackConfiguration, Target

        target = Target(url="https://example.test/search", query={"q": "test"})
        cfg = AttackConfiguration(
            target=target,
            parameter="q",
            injection_location="query",
            detector_value="Welcome",
        )
        config_summary(cfg)
        self.assertIn("example.test", self.output)
        self.assertIn("boolean", self.output)
        self.assertIn("text", self.output)


if __name__ == "__main__":
    unittest.main()
