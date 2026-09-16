"""Tests for package boundaries and lightweight imports."""

import subprocess
import sys
import unittest


class PackagingTests(unittest.TestCase):
    def test_transport_contract_import_does_not_load_requests(self) -> None:
        result = subprocess.run(
            [
                sys.executable,
                "-c",
                "import sys; import transport; print('requests' in sys.modules)",
            ],
            check=True,
            capture_output=True,
            text=True,
        )
        self.assertEqual(result.stdout.strip(), "False")

    def test_lazy_requests_adapter_remains_public(self) -> None:
        from transport import HttpClient, RequestsHttpClient

        self.assertTrue(issubclass(RequestsHttpClient, HttpClient))


if __name__ == "__main__":
    unittest.main()
