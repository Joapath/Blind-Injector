"""Unit tests for the rate-limiting HttpClient decorator."""

import unittest

from core.rate_limiter import RateLimiter
from models import HttpResponseData, RequestData
from transport import HttpClient, RateLimitedHttpClient


class RecordingHttpClient(HttpClient):
    def __init__(self) -> None:
        self.requests: list[RequestData] = []

    def send(self, request: RequestData) -> HttpResponseData:
        self.requests.append(request)
        return HttpResponseData(200, "ok")


class RateLimitedHttpClientTests(unittest.TestCase):
    def test_delegates_to_inner_client(self) -> None:
        inner = RecordingHttpClient()
        client = RateLimitedHttpClient(inner, RateLimiter(None))
        request = RequestData("https://example.test/")

        response = client.send(request)

        self.assertEqual(inner.requests, [request])
        self.assertEqual(response.status_code, 200)

    def test_acquires_a_slot_before_every_send(self) -> None:
        calls: list[str] = []

        class RecordingLimiter(RateLimiter):
            def acquire(self) -> None:
                calls.append("acquire")

        inner = RecordingHttpClient()
        client = RateLimitedHttpClient(inner, RecordingLimiter(None))

        client.send(RequestData("https://example.test/"))
        client.send(RequestData("https://example.test/"))

        self.assertEqual(calls, ["acquire", "acquire"])
        self.assertEqual(len(inner.requests), 2)


if __name__ == "__main__":
    unittest.main()
