"""Tests for high-level attack orchestration."""

import unittest

from core import BlindAttackEngine
from models import ExtractionResult


class FakeExtractor:
    def __init__(self) -> None:
        self.expressions = []

    def extract(self, expression: str) -> ExtractionResult:
        self.expressions.append(expression)
        return ExtractionResult(expression, f"value:{expression}")


class FakeTechnique:
    def __init__(self) -> None:
        self.calls: list[str] = []

    def validate(self) -> bool:
        self.calls.append("validate")
        return True

    def probe(self) -> bool:
        self.calls.append("probe")
        return True

    def confirm(self) -> bool:
        self.calls.append("confirm")
        return True

    def extract(self, expression: str):
        self.calls.append(f"extract:{expression}")
        return ExtractionResult(expression, f"value:{expression}")


class AttackEngineTests(unittest.TestCase):
    def test_delegates_distinct_expressions_and_groups_results(self) -> None:
        extractor = FakeExtractor()
        result = BlindAttackEngine(extractor).run(("database()", "current_user()"))

        self.assertEqual(extractor.expressions, ["database()", "current_user()"])
        self.assertEqual(result.extractions["database()"].value, "value:database()")
        self.assertEqual(result.extractions["current_user()"].value, "value:current_user()")
        with self.assertRaises(TypeError):
            result.extractions["new"] = None  # type: ignore[index]

    def test_runs_technique_orchestration_before_extraction(self) -> None:
        technique = FakeTechnique()
        result = BlindAttackEngine(technique).run(("database()", "current_user()"))

        self.assertEqual(
            technique.calls,
            [
                "validate",
                "probe",
                "confirm",
                "extract:database()",
                "extract:current_user()",
            ],
        )
        self.assertEqual(result.extractions["database()"].value, "value:database()")

    def test_allows_empty_worklist(self) -> None:
        result = BlindAttackEngine(FakeExtractor()).run(())
        self.assertEqual(dict(result.extractions), {})

    def test_rejects_empty_and_duplicate_expressions(self) -> None:
        engine = BlindAttackEngine(FakeExtractor())
        with self.assertRaises(ValueError):
            engine.run(("",))
        with self.assertRaises(ValueError):
            engine.run(("database()", "database()"))


if __name__ == "__main__":
    unittest.main()