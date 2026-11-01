"""Parse a raw HTTP request (Burp "Copy to file"/"Save item" style) into a
``Target`` plus, optionally, an auto-detected injection point.

Presentation-layer parsing, no network I/O -- same role as ``cli/report.py``.
The injection point is marked with a literal ``*`` at the end of one query,
body, or cookie value (same convention as sqlmap's ``-r``). Anything
ambiguous (marker in more than one place, marker not at the end of a value,
marker somewhere this project cannot inject into, an unsupported body
content type, a missing Host header) raises ``ValueError`` with an explicit
message -- never a silent guess.
"""

from dataclasses import dataclass
from urllib.parse import parse_qsl

from models.target import Target

_MARKER = "*"
_DROPPED_HEADERS = {"content-length"}


@dataclass(frozen=True, slots=True)
class ParsedRequest:
    """Result of parsing one raw request file."""

    target: Target
    parameter: str | None = None
    injection_location: str | None = None


def _parse_request_line(line: str) -> tuple[str, str, str]:
    parts = line.split()
    if len(parts) < 2:
        raise ValueError(f"malformed request line: {line!r}")
    method, target = parts[0], parts[1]
    path, _, query_string = target.partition("?")
    return method.upper(), path, query_string


def _parse_headers(lines: list[str]) -> tuple[dict[str, str], dict[str, str], str | None]:
    headers: dict[str, str] = {}
    cookies: dict[str, str] = {}
    host: str | None = None
    for line in lines:
        if not line.strip():
            continue
        name, separator, value = line.partition(":")
        if not separator:
            raise ValueError(f"malformed header line: {line!r}")
        name = name.strip()
        value = value.strip()
        if name.lower() == "cookie":
            for chunk in value.split(";"):
                chunk = chunk.strip()
                if not chunk:
                    continue
                cookie_name, _, cookie_value = chunk.partition("=")
                cookies[cookie_name.strip()] = cookie_value.strip()
            continue
        if name.lower() == "host":
            host = value
            continue
        if name.lower() in _DROPPED_HEADERS:
            continue
        headers[name] = value
    return headers, cookies, host


def _parse_body(method: str, body: str, headers: dict[str, str]) -> dict[str, str]:
    if method != "POST" or not body.strip():
        return {}
    content_type = next(
        (value for name, value in headers.items() if name.lower() == "content-type"), None
    )
    if content_type is not None and "x-www-form-urlencoded" not in content_type.lower():
        raise ValueError(
            f"unsupported body Content-Type for --request-file: {content_type!r}; "
            "only application/x-www-form-urlencoded is parsed today -- build the "
            "request with --body KEY=VALUE manually instead"
        )
    if content_type is None:
        print(
            "[request-file] no Content-Type header; assuming "
            "application/x-www-form-urlencoded for the body"
        )
    return dict(parse_qsl(body.strip(), keep_blank_values=True))


def _find_marker(
    query: dict[str, str], body: dict[str, str], cookies: dict[str, str]
) -> tuple[str | None, str | None]:
    # Only query/body/cookie values are injectable, so only those are scanned
    # for the marker. Headers and the path are intentionally NOT scanned: a
    # literal '*' appears legitimately in common headers (e.g. `Accept: */*`),
    # and treating it as a misplaced marker would be a false positive. Marking
    # a header/path for injection is unsupported; such a request simply parses
    # with no detected marker, and the user passes --parameter/--location.
    matches: list[tuple[str, str]] = []
    for location, values in (("query", query), ("body", body), ("cookie", cookies)):
        for name, value in values.items():
            if _MARKER in value:
                matches.append((location, name))

    if not matches:
        return None, None
    if len(matches) > 1:
        found = ", ".join(f"{location}:{name}" for location, name in matches)
        raise ValueError(
            f"'*' marker found in more than one place ({found}); mark exactly one "
            "parameter, or drop the extra markers"
        )

    location, name = matches[0]
    values = {"query": query, "body": body, "cookie": cookies}[location]
    value = values[name]
    if not value.endswith(_MARKER):
        raise ValueError(
            f"'*' marker in {location}:{name} must be at the end of the value; "
            "mid-value injection isn't supported yet"
        )
    values[name] = value[: -len(_MARKER)]
    return name, location


def parse_request_file(text: str, *, force_ssl: bool = False) -> ParsedRequest:
    """Parse a raw HTTP request captured from Burp/a browser into a ``Target``.

    ``force_ssl`` picks the scheme (raw requests never carry one): False
    (default, matching sqlmap's own ``-r`` convention) builds ``http://``,
    True builds ``https://``.
    """
    normalized = text.replace("\r\n", "\n")
    header_block, _, body_text = normalized.partition("\n\n")
    lines = header_block.split("\n")
    if not lines or not lines[0].strip():
        raise ValueError("request file is empty or missing a request line")

    method, path, query_string = _parse_request_line(lines[0])
    headers, cookies, host = _parse_headers(lines[1:])

    if not host:
        raise ValueError("request file is missing a Host header")

    query = dict(parse_qsl(query_string, keep_blank_values=True))
    body = _parse_body(method, body_text, headers)

    parameter, injection_location = _find_marker(query, body, cookies)

    scheme = "https" if force_ssl else "http"
    target = Target(
        url=f"{scheme}://{host}{path}",
        method=method,
        headers=headers,
        cookies=cookies,
        query=query,
        body=body,
    )
    return ParsedRequest(target=target, parameter=parameter, injection_location=injection_location)
