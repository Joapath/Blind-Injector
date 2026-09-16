"""Import smoke tests for the package boundaries."""

import unittest


class ImportTests(unittest.TestCase):
    def test_public_contracts_import_without_external_http_dependency(self) -> None:
        from core import AttackEngine, Extractor, SearchStrategy
        from detection import Detector
        from transport import HttpClient
        from payloads import ConditionBuilder, InjectionPoint, PayloadBuilder

        self.assertTrue(all((AttackEngine, Extractor, SearchStrategy, Detector, HttpClient)))
        self.assertTrue(all((ConditionBuilder, InjectionPoint, PayloadBuilder)))


if __name__ == "__main__":
    unittest.main()
