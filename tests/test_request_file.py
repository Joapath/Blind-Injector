"""Unit tests for raw-request parsing (cli/request_file.py)."""

import unittest

from cli.request_file import parse_request_file


def _request(cookie: str, extra_headers: str = "", body: str = "") -> str:
    return (
        "GET /filter?category=Gifts HTTP/2\r\n"
        "Host: example.test\r\n"
        f"Cookie: {cookie}\r\n"
        f"{extra_headers}"
        "\r\n"
        f"{body}"
    )


class ParseRequestFileTests(unittest.TestCase):
    def test_parses_method_url_headers_cookies_query(self) -> None:
        text = _request(
            "TrackingId=abc123; session=xyz",
            extra_headers="User-Agent: curl/8.0\r\nHost-Length: ignored\r\n",
        )
        parsed = parse_request_file(text)

        self.assertEqual(parsed.target.method, "GET")
        self.assertEqual(parsed.target.url, "http://example.test/filter")
        self.assertEqual(dict(parsed.target.query), {"category": "Gifts"})
        self.assertEqual(
            dict(parsed.target.cookies), {"TrackingId": "abc123", "session": "xyz"}
        )
        self.assertEqual(parsed.target.headers.get("User-Agent"), "curl/8.0")
        self.assertIsNone(parsed.parameter)
        self.assertIsNone(parsed.injection_location)

    def test_force_ssl_builds_https_url(self) -> None:
        text = _request("TrackingId=abc123")
        parsed = parse_request_file(text, force_ssl=True)
        self.assertTrue(parsed.target.url.startswith("https://"))

    def test_drops_host_and_content_length_headers(self) -> None:
        text = _request(
            "TrackingId=abc123",
            extra_headers="Content-Length: 999\r\n",
        )
        parsed = parse_request_file(text)
        self.assertNotIn("Content-Length", parsed.target.headers)
        self.assertNotIn("Host", parsed.target.headers)

    def test_detects_marker_in_cookie(self) -> None:
        text = _request("TrackingId=abc123*; session=xyz")
        parsed = parse_request_file(text)

        self.assertEqual(parsed.parameter, "TrackingId")
        self.assertEqual(parsed.injection_location, "cookie")
        self.assertEqual(parsed.target.cookies["TrackingId"], "abc123")

    def test_detects_marker_in_query(self) -> None:
        text = (
            "GET /filter?category=Gifts* HTTP/2\r\n"
            "Host: example.test\r\n"
            "Cookie: session=xyz\r\n"
            "\r\n"
        )
        parsed = parse_request_file(text)

        self.assertEqual(parsed.parameter, "category")
        self.assertEqual(parsed.injection_location, "query")
        self.assertEqual(parsed.target.query["category"], "Gifts")

    def test_detects_marker_in_body(self) -> None:
        text = (
            "POST /login HTTP/2\r\n"
            "Host: example.test\r\n"
            "Content-Type: application/x-www-form-urlencoded\r\n"
            "Cookie: session=xyz\r\n"
            "\r\n"
            "username=admin*&password=secret"
        )
        parsed = parse_request_file(text)

        self.assertEqual(parsed.parameter, "username")
        self.assertEqual(parsed.injection_location, "body")
        self.assertEqual(parsed.target.body["username"], "admin")
        self.assertEqual(parsed.target.body["password"], "secret")

    def test_body_without_content_type_is_parsed_with_a_note(self) -> None:
        text = (
            "POST /login HTTP/2\r\n"
            "Host: example.test\r\n"
            "Cookie: session=xyz\r\n"
            "\r\n"
            "username=admin&password=secret"
        )
        parsed = parse_request_file(text)
        self.assertEqual(parsed.target.body["username"], "admin")

    def test_rejects_unsupported_body_content_type(self) -> None:
        text = (
            "POST /login HTTP/2\r\n"
            "Host: example.test\r\n"
            "Content-Type: application/json\r\n"
            "Cookie: session=xyz\r\n"
            "\r\n"
            '{"username": "admin"}'
        )
        with self.assertRaises(ValueError):
            parse_request_file(text)

    def test_rejects_multiple_markers(self) -> None:
        text = _request("TrackingId=abc123*; session=xyz*")
        with self.assertRaises(ValueError):
            parse_request_file(text)

    def test_rejects_marker_not_at_end_of_value(self) -> None:
        text = _request("TrackingId=abc*123; session=xyz")
        with self.assertRaises(ValueError):
            parse_request_file(text)

    def test_ignores_asterisk_in_accept_header(self) -> None:
        # `Accept: */*` is normal content, not a misplaced marker.
        text = _request("session=xyz", extra_headers="Accept: text/html,*/*;q=0.8\r\n")
        parsed = parse_request_file(text)
        self.assertIsNone(parsed.parameter)
        self.assertEqual(parsed.target.headers["Accept"], "text/html,*/*;q=0.8")

    def test_marker_in_path_or_header_is_not_detected(self) -> None:
        # Unsupported injection points: no marker is detected, no error raised;
        # the caller falls back to --parameter/--location.
        text = (
            "GET /filter*?category=Gifts HTTP/2\r\n"
            "Host: example.test\r\n"
            "Cookie: session=xyz\r\n"
            "\r\n"
        )
        parsed = parse_request_file(text)
        self.assertIsNone(parsed.parameter)

    def test_requires_host_header(self) -> None:
        text = "GET /filter?category=Gifts HTTP/2\r\nCookie: session=xyz\r\n\r\n"
        with self.assertRaises(ValueError):
            parse_request_file(text)

    def test_rejects_empty_request(self) -> None:
        with self.assertRaises(ValueError):
            parse_request_file("")


if __name__ == "__main__":
    unittest.main()
