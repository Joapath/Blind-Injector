"""Injection points for query, body, and cookie parameters."""

from dataclasses import dataclass

from models.http import RequestData

from .contracts import InjectionPoint


def _with_payload(values: dict[str, str], parameter: str, payload: str) -> dict[str, str]:
    if not parameter:
        raise ValueError("parameter cannot be empty")
    if parameter not in values:
        raise KeyError(f"Parameter not found: {parameter}")
    values[parameter] = f"{values[parameter]}{payload}"
    return values


@dataclass(frozen=True, slots=True)
class QueryParameterInjectionPoint(InjectionPoint):
    """Append a payload to one query-string parameter."""

    parameter: str

    def inject(self, request: RequestData, payload: str) -> RequestData:
        query = _with_payload(dict(request.query), self.parameter, payload)
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
    """Append a payload to one form body parameter."""

    parameter: str

    def inject(self, request: RequestData, payload: str) -> RequestData:
        body = _with_payload(dict(request.body), self.parameter, payload)
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
    """Append a payload to one cookie value."""

    parameter: str

    def inject(self, request: RequestData, payload: str) -> RequestData:
        cookies = _with_payload(dict(request.cookies), self.parameter, payload)
        return RequestData(
            url=request.url,
            method=request.method,
            headers=request.headers,
            cookies=cookies,
            query=request.query,
            body=request.body,
        )