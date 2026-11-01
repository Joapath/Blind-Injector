"""Injection points for query, body, and cookie parameters."""

from dataclasses import dataclass

from models.http import RequestData

from .contracts import InjectionPoint


_INJECTION_MODES = frozenset({"append", "replace"})


def _validate_mode(mode: str) -> None:
    if mode not in _INJECTION_MODES:
        raise ValueError("mode must be append or replace")


def _with_payload(
    values: dict[str, str], parameter: str, payload: str, mode: str
) -> dict[str, str]:
    if not parameter:
        raise ValueError("parameter cannot be empty")
    _validate_mode(mode)
    if parameter not in values:
        raise KeyError(f"Parameter not found: {parameter}")
    values[parameter] = f"{values[parameter]}{payload}" if mode == "append" else payload
    return values


@dataclass(frozen=True, slots=True)
class QueryParameterInjectionPoint(InjectionPoint):
    """Inject a payload into one query-string parameter."""

    parameter: str
    mode: str = "append"

    def __post_init__(self) -> None:
        _validate_mode(self.mode)

    def inject(self, request: RequestData, payload: str) -> RequestData:
        query = _with_payload(dict(request.query), self.parameter, payload, self.mode)
        return RequestData(
            url=request.url,
            method=request.method,
            headers=request.headers,
            cookies=request.cookies,
            query=query,
            body=request.body,
        )


@dataclass(frozen=True, slots=True)
class BodyParameterInjectionPoint(InjectionPoint):
    """Inject a payload into one form body parameter."""

    parameter: str
    mode: str = "append"

    def __post_init__(self) -> None:
        _validate_mode(self.mode)

    def inject(self, request: RequestData, payload: str) -> RequestData:
        body = _with_payload(dict(request.body), self.parameter, payload, self.mode)
        return RequestData(
            url=request.url,
            method=request.method,
            headers=request.headers,
            cookies=request.cookies,
            query=request.query,
            body=body,
        )


@dataclass(frozen=True, slots=True)
class CookieInjectionPoint(InjectionPoint):
    """Inject a payload into one cookie value."""

    parameter: str
    mode: str = "append"

    def __post_init__(self) -> None:
        _validate_mode(self.mode)

    def inject(self, request: RequestData, payload: str) -> RequestData:
        cookies = _with_payload(dict(request.cookies), self.parameter, payload, self.mode)
        return RequestData(
            url=request.url,
            method=request.method,
            headers=request.headers,
            cookies=cookies,
            query=request.query,
            body=request.body,
        )