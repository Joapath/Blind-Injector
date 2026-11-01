"""Unit tests for the header-mutating HttpClient decorator."""

import unittest

from core.header_mutators import HeaderMutator
from models import HttpResponseData, RequestData
from transport import HeaderMutatingHttpClient, HttpClient


class RecordingHttpClient(HttpClient):
    def __init__(self) -> None:
        self.requests: list[RequestData] = []

    def send(self, request: RequestData) -> HttpResponseData:
        self.requests.append(request)
        return HttpResponseData(200, "ok")


class FixedHeaderMutator(HeaderMutator):
    def __init__(self, headers: dict[str, str]) -> None:
        self._headers = headers

    def headers_for_request(self) -> dict[str, str]:
        return dict(self._headers)


class HeaderMutatingHttpClientTests(unittest.TestCase):
    def test_merges_mutator_headers_over_the_original_request(self) -> None:
        inner = RecordingHttpClient()
        client = HeaderMutatingHttpClient(
            inner, (FixedHeaderMutator({"User-Agent": "mutated"}),)
        )
        request = RequestData("https://example.test/", headers={"X-Kept": "yes"})

        client.send(request)

        sent = inner.requests[0]
        self.assertEqual(sent.headers["User-Agent"], "mutated")
        self.assertEqual(sent.headers["X-Kept"], "yes")

    def test_later_mutators_override_earlier_ones(self) -> None:
        inner = RecordingHttpClient()
        client = HeaderMutatingHttpClient(
            inner,
            (
                FixedHeaderMutator({"User-Agent": "first"}),
                FixedHeaderMutator({"User-Agent": "second"}),
            ),
        )

        client.send(RequestData("https://example.test/"))

        self.assertEqual(inner.requests[0].headers["User-Agent"], "second")

    def test_no_mutators_leaves_headers_untouched(self) -> None:
        inner = RecordingHttpClient()
        client = HeaderMutatingHttpClient(inner, ())
        request = RequestData("https://example.test/", headers={"X-Kept": "yes"})

        client.send(request)

        self.assertEqual(dict(inner.requests[0].headers), {"X-Kept": "yes"})

    def test_does_not_mutate_query_cookies_or_body(self) -> None:
        inner = RecordingHttpClient()
        client = HeaderMutatingHttpClient(inner, (FixedHeaderMutator({"User-Agent": "x"}),))
        request = RequestData(
            "https://example.test/",
            method="POST",
            cookies={"session": "abc"},
            query={"q": "1"},
            body={"f": "2"},
        )

        client.send(request)

        sent = inner.requests[0]
        self.assertEqual(dict(sent.cookies), {"session": "abc"})
        self.assertEqual(dict(sent.query), {"q": "1"})
        self.assertEqual(dict(sent.body), {"f": "2"})
        self.assertEqual(sent.method, "POST")


if __name__ == "__main__":
    unittest.main()
