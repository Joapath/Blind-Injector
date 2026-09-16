"""Tests for the Requests transport adapter without network access."""

import unittest
from unittest.mock import Mock, patch

import requests

from exceptions import HttpRequestError
from models import RequestData
from transport import RequestsHttpClient


class RequestsHttpClientTests(unittest.TestCase):
    @patch("transport.requests_client.requests.Session")
    def test_maps_request_and_normalizes_response(self, session_factory: Mock) -> None:
        request_call = session_factory.return_value.request
        response = Mock(status_code=201, text="accepted", headers={"X-Test": "yes"})
        request_call.return_value = response
        request = RequestData(
            "https://example.test/submit",
            method="POST",
            headers={"X-Client": "blind-finder"},
            cookies={"session": "value"},
            query={"page": "1"},
            body={"name": "alice"},
        )

        result = RequestsHttpClient(timeout=3, verify_ssl=False).send(request)

        self.assertEqual(result.status_code, 201)
        self.assertEqual(result.text, "accepted")
        self.assertEqual(dict(result.headers), {"X-Test": "yes"})
        request_call.assert_called_once_with(
            method="POST",
            url="https://example.test/submit",
            headers={"X-Client": "blind-finder"},
            cookies={"session": "value"},
            params={"page": "1"},
            data={"name": "alice"},
            timeout=3,
            verify=False,
            proxies=None,
            allow_redirects=False,
        )

    @patch("transport.requests_client.requests.Session")
    def test_wraps_requests_errors(self, session_factory: Mock) -> None:
        request_call = session_factory.return_value.request
        request_call.side_effect = requests.Timeout("timed out")

        with self.assertRaises(HttpRequestError) as context:
            RequestsHttpClient().send(RequestData("https://example.test"))

        self.assertEqual(context.exception.url, "https://example.test")
        self.assertIsInstance(context.exception.cause, requests.Timeout)

    def test_rejects_invalid_timeout(self) -> None:
        with self.assertRaises(ValueError):
            RequestsHttpClient(timeout=0)

    def test_rejects_invalid_retry_configuration(self) -> None:
        with self.assertRaises(ValueError):
            RequestsHttpClient(max_retries=-1)
        with self.assertRaises(ValueError):
            RequestsHttpClient(retry_backoff=-1)

    @patch("transport.requests_client.requests.Session")
    def test_passes_explicit_redirect_policy(self, session_factory: Mock) -> None:
        session_factory.return_value.request.return_value = Mock(
            status_code=200, text="ok", headers={}
        )
        RequestsHttpClient(allow_redirects=True).send(RequestData("https://example.test"))
        self.assertTrue(session_factory.return_value.request.call_args.kwargs["allow_redirects"])


if __name__ == "__main__":
    unittest.main()