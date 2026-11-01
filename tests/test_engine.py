"""Tests for high-level attack orchestration."""

import threading
import unittest

from core import BlindAttackEngine
from models import CharacterResult, ExtractionResult


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

    def collect_evidence(self):
        return type(
            "Evidence",
            (),
            {"oracle_valid": True, "to_dict": lambda self: {}},
        )()


class FakeInvalidOracleTechnique(FakeTechnique):
    def probe(self) -> bool:
        self.calls.append("probe")
        return True

    def confirm(self) -> bool:
        self.calls.append("confirm")
        return True

    def collect_evidence(self):
        return type(
            "Evidence",
            (),
            {"oracle_valid": False, "to_dict": lambda self: {}},
        )()


class ResumeAwareExtractor:
    """An Extractor that records whether resume_from was forwarded."""

    def __init__(self) -> None:
        self.calls: list[tuple[str, tuple]] = []

    def extract(self, expression: str, *, resume_from: tuple = ()) -> ExtractionResult:
        self.calls.append((expression, resume_from))
        return ExtractionResult(expression, "resumed" if resume_from else "fresh")


class RecordingTechniqueFactory:
    """Mint a fresh FakeTechnique per call, recording every instance made."""

    def __init__(self) -> None:
        self.instances: list[FakeTechnique] = []
        self._lock = threading.Lock()

    def __call__(self) -> FakeTechnique:
        technique = FakeTechnique()
        with self._lock:
            self.instances.append(technique)
        return technique


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

    def test_rejects_invalid_oracle_after_confirmation(self) -> None:
        engine = BlindAttackEngine(FakeInvalidOracleTechnique())
        with self.assertRaises(ValueError):
            engine.run(("database()",))

    def test_rejects_empty_and_duplicate_expressions(self) -> None:
        engine = BlindAttackEngine(FakeExtractor())
        with self.assertRaises(ValueError):
            engine.run(("",))
        with self.assertRaises(ValueError):
            engine.run(("database()", "database()"))

    def test_rejects_non_positive_max_workers(self) -> None:
        with self.assertRaises(ValueError):
            BlindAttackEngine(FakeExtractor(), max_workers=0)

    def test_requires_factory_when_max_workers_greater_than_one(self) -> None:
        with self.assertRaises(ValueError):
            BlindAttackEngine(FakeExtractor(), max_workers=2)

    def test_default_max_workers_runs_sequentially_on_the_primary_instance(self) -> None:
        extractor = FakeExtractor()
        result = BlindAttackEngine(extractor, max_workers=1).run(("a()", "b()"))

        self.assertEqual(extractor.expressions, ["a()", "b()"])
        self.assertEqual(result.extractions["a()"].value, "value:a()")

    def test_parallel_extraction_runs_oracle_once_and_extracts_on_fresh_instances(self) -> None:
        primary = FakeTechnique()
        factory = RecordingTechniqueFactory()
        engine = BlindAttackEngine(primary, extractor_factory=factory, max_workers=3)

        result = engine.run(("database()", "current_user()", "version()"))

        # Oracle validation ran exactly once, on the primary instance, and
        # never performed any extraction itself.
        self.assertEqual(primary.calls, ["validate", "probe", "confirm"])
        # Every expression got its own, distinct worker instance.
        self.assertEqual(len(factory.instances), 3)
        self.assertEqual(len({id(worker) for worker in factory.instances}), 3)
        self.assertEqual(
            {expr: extraction.value for expr, extraction in result.extractions.items()},
            {
                "database()": "value:database()",
                "current_user()": "value:current_user()",
                "version()": "value:version()",
            },
        )

    def test_single_expression_skips_the_thread_pool_even_with_workers(self) -> None:
        extractor = FakeExtractor()

        def unused_factory() -> FakeExtractor:
            raise AssertionError("factory should not be used for a single expression")

        engine = BlindAttackEngine(extractor, extractor_factory=unused_factory, max_workers=4)
        result = engine.run(("database()",))

        self.assertEqual(result.extractions["database()"].value, "value:database()")

    def test_resume_forwards_resume_from_only_for_matching_expression(self) -> None:
        extractor = ResumeAwareExtractor()
        engine = BlindAttackEngine(extractor)
        resume_data = {"database()": (CharacterResult(1, "a"),)}

        result = engine.run(("database()", "current_user()"), resume=resume_data)

        self.assertEqual(result.extractions["database()"].value, "resumed")
        self.assertEqual(result.extractions["current_user()"].value, "fresh")
        self.assertEqual(extractor.calls[0], ("database()", resume_data["database()"]))
        self.assertEqual(extractor.calls[1], ("current_user()", ()))


if __name__ == "__main__":
    unittest.main()