"""Contract tests for the conceptual technique layer."""

import unittest

from core.blind_technique import BlindTechnique
from core.boolean_technique import BooleanTechnique
from models.attack import ExtractionResult
from models.http import HttpResponseData, RequestData
from payloads import QueryParameterInjectionPoint


class FakeExtractor:
    """Small deterministic collaborator for testing technique orchestration."""

    def __init__(self, outcomes: dict[str, bool]) -> None:
        self.outcomes = outcomes
        self.calls: list[str] = []
        self._last_request: RequestData | None = None
        self._last_response: HttpResponseData | None = None
        self._last_payload: str | None = None
        self._request = RequestData(
            "https://example.test",
            query={"tracking": "base"},
        )
        self._injection_point = QueryParameterInjectionPoint("tracking")

    def test_condition(self, condition: str) -> bool:
        self.calls.append(condition)
        self._last_payload = f"PAYLOAD:{condition}"
        self._last_request = self._injection_point.inject(
            self._request, self._last_payload
        )
        result = self.outcomes[condition]
        self._last_response = HttpResponseData(200, "TRUE" if result else "FALSE")
        return result

    @property
    def last_request(self) -> RequestData | None:
        return self._last_request

    @property
    def last_response(self) -> HttpResponseData | None:
        return self._last_response

    @property
    def last_payload(self) -> str | None:
        return self._last_payload

    @property
    def injection_point(self) -> QueryParameterInjectionPoint:
        return self._injection_point

    @property
    def base_request(self) -> RequestData:
        return self._request

    def extract(self, expression: str) -> ExtractionResult:
        return ExtractionResult(expression, "secret")


class ExampleBlindTechnique(BlindTechnique):
    def _true_condition(self) -> str:
        return "1=1"

    def _false_condition(self) -> str:
        return "1=2"


class BlindTechniqueTests(unittest.TestCase):
    def test_validate_checks_distinct_non_empty_conditions(self) -> None:
        technique = ExampleBlindTechnique(
            FakeExtractor({"1=1": True, "1=2": False})
        )
        self.assertTrue(technique.validate())

    def test_probe_and_confirm_require_different_oracle_results(self) -> None:
        extractor = FakeExtractor({"1=1": True, "1=2": False})
        technique = ExampleBlindTechnique(extractor)

        self.assertTrue(technique.probe())
        self.assertTrue(technique.confirm())
        self.assertEqual(extractor.calls, ["1=1", "1=2", "1=1", "1=2"])

        evidence = technique.collect_evidence()
        self.assertEqual(evidence.confidence.value, "confirmed")
        self.assertEqual(evidence.payload, "PAYLOAD:1=1")
        self.assertEqual(evidence.raw_request["query"]["tracking"], "basePAYLOAD:1=1")
        self.assertEqual(evidence.raw_response["text"], "TRUE")
        self.assertEqual(evidence.extracted_data, None)

    def test_failed_confirmation_does_not_become_confirmed(self) -> None:
        extractor = FakeExtractor({"1=1": True, "1=2": False})
        technique = ExampleBlindTechnique(extractor)
        self.assertTrue(technique.probe())

        extractor.outcomes["1=2"] = True
        self.assertFalse(technique.confirm())
        self.assertEqual(technique.collect_evidence().confidence.value, "probable")

    def test_extract_delegates_without_reimplementing_search(self) -> None:
        extractor = FakeExtractor({"1=1": True, "1=2": False})
        technique = ExampleBlindTechnique(extractor)

        result = technique.extract("password")

        self.assertEqual(result.value, "secret")
        evidence = technique.collect_evidence()
        self.assertEqual(evidence.extracted_data, "secret")

    def test_collect_evidence_requires_a_previous_operation(self) -> None:
        technique = ExampleBlindTechnique(
            FakeExtractor({"1=1": True, "1=2": False})
        )
        with self.assertRaises(RuntimeError):
            technique.collect_evidence()


class BooleanTechniqueTests(unittest.TestCase):
    def test_uses_default_true_and_false_conditions(self) -> None:
        extractor = FakeExtractor({"1=1": True, "1=2": False})
        technique = BooleanTechnique(extractor)

        self.assertTrue(technique.validate())
        self.assertTrue(technique.probe())
        self.assertEqual(extractor.calls, ["1=1", "1=2"])

    def test_allows_dialect_or_context_specific_conditions(self) -> None:
        extractor = FakeExtractor({"TRUE": True, "FALSE": False})
        technique = BooleanTechnique(
            extractor,
            true_condition="TRUE",
            false_condition="FALSE",
        )

        self.assertTrue(technique.validate())
        self.assertTrue(technique.confirm())
        self.assertEqual(extractor.calls, ["TRUE", "FALSE"])

    def test_rejects_empty_or_identical_conditions(self) -> None:
        extractor = FakeExtractor({"": True, "1=1": True})
        self.assertFalse(
            BooleanTechnique(
                extractor,
                true_condition="",
                false_condition="1=2",
            ).validate()
        )
        self.assertFalse(
            BooleanTechnique(
                extractor,
                true_condition="1=1",
                false_condition="1=1",
            ).validate()
        )


if __name__ == "__main__":
    unittest.main()
