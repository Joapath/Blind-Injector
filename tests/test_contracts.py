"""Tests that the public contracts remain abstract and usable with fakes."""

import unittest

from core import AttackEngine, Extractor, SearchStrategy
from detection import Detector
from transport import HttpClient
from models import HttpResponseData, RequestData
from payloads import ConditionBuilder, InjectionPoint, PayloadBuilder


class ContractTests(unittest.TestCase):
    def test_contracts_cannot_be_instantiated_directly(self) -> None:
        contracts = (
            AttackEngine,
            Extractor,
            SearchStrategy,
            Detector,
            HttpClient,
            ConditionBuilder,
            InjectionPoint,
            PayloadBuilder,
        )
        for contract in contracts:
            with self.subTest(contract=contract.__name__), self.assertRaises(TypeError):
                contract()

    def test_fake_http_client_returns_normalized_response(self) -> None:
        class FakeHttpClient(HttpClient):
            def send(self, request: RequestData) -> HttpResponseData:
                return HttpResponseData(200, request.url)

        response = FakeHttpClient().send(RequestData("https://example.test"))
        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.text, "https://example.test")

    def test_search_strategy_can_be_driven_by_a_plain_predicate(self) -> None:
        class FakeSearch(SearchStrategy):
            @property
            def comparison_operator(self):
                return "="

            def find(self, position: int, charset: str, predicate):
                return next((char for char in charset if predicate(ord(char))), "")

        result = FakeSearch().find(1, "abc", lambda value: value >= ord("b"))
        self.assertEqual(result, "b")


if __name__ == "__main__":
    unittest.main()
