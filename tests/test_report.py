"""Unit tests for the exportable run report (cli/report.py)."""

import csv
import json
import tempfile
import unittest
from datetime import datetime, timedelta, timezone
from pathlib import Path

from cli.report import build_report, write_report
from models import AttackConfiguration, AttackResult, CharacterResult, ExtractionResult, Target


def _configuration() -> AttackConfiguration:
    return AttackConfiguration(
        target=Target("https://example.test/filter", query={"tracking": "base"}),
        parameter="tracking",
        detector_value="TRUE",
    )


def _result() -> AttackResult:
    return AttackResult(
        {
            "username": ExtractionResult(
                "username",
                "admin",
                characters=tuple(CharacterResult(i + 1, c, attempts=3) for i, c in enumerate("admin")),
                complete=True,
            ),
            "password_hash": ExtractionResult(
                "password_hash",
                "ab",
                characters=(
                    CharacterResult(1, "a", attempts=4),
                    CharacterResult(2, "b", attempts=5),
                ),
                complete=False,
            ),
        }
    )


class BuildReportTests(unittest.TestCase):
    def test_includes_run_metadata_and_per_expression_summary(self) -> None:
        started = datetime(2026, 1, 1, 12, 0, 0, tzinfo=timezone.utc)
        finished = started + timedelta(seconds=12.5)

        report = build_report(_configuration(), _result(), started_at=started, finished_at=finished)

        self.assertEqual(report["target"], "https://example.test/filter")
        self.assertEqual(report["parameter"], "tracking")
        self.assertEqual(report["technique"], "boolean")
        self.assertEqual(report["duration_seconds"], 12.5)

        by_expression = {row["expression"]: row for row in report["extractions"]}
        self.assertEqual(by_expression["username"]["value"], "admin")
        self.assertTrue(by_expression["username"]["complete"])
        self.assertEqual(by_expression["username"]["length"], 5)
        self.assertEqual(by_expression["username"]["requests"], 15)  # 5 * 3
        self.assertFalse(by_expression["password_hash"]["complete"])
        self.assertEqual(by_expression["password_hash"]["requests"], 9)  # 4 + 5

    def test_report_is_json_serializable(self) -> None:
        started = datetime(2026, 1, 1, tzinfo=timezone.utc)
        report = build_report(_configuration(), _result(), started_at=started, finished_at=started)

        json.dumps(report)  # must not raise


class WriteReportTests(unittest.TestCase):
    def setUp(self) -> None:
        started = datetime(2026, 1, 1, tzinfo=timezone.utc)
        self.report = build_report(
            _configuration(), _result(), started_at=started, finished_at=started + timedelta(seconds=1)
        )

    def test_writes_json(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "report.json"
            write_report(self.report, path, "json")

            loaded = json.loads(path.read_text(encoding="utf-8"))
            self.assertEqual(loaded["target"], self.report["target"])

    def test_writes_csv_with_one_row_per_expression(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "report.csv"
            write_report(self.report, path, "csv")

            with path.open(encoding="utf-8") as handle:
                rows = list(csv.DictReader(handle))
            self.assertEqual(len(rows), 2)
            self.assertEqual({row["expression"] for row in rows}, {"username", "password_hash"})

    def test_creates_missing_parent_directories(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "nested" / "dir" / "report.json"
            write_report(self.report, path, "json")
            self.assertTrue(path.exists())

    def test_rejects_unsupported_format(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            with self.assertRaises(ValueError):
                write_report(self.report, Path(tmp) / "report.xml", "xml")


if __name__ == "__main__":
    unittest.main()
