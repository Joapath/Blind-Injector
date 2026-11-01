"""HttpClient decorator that applies per-request header mutations."""

from core.header_mutators import HeaderMutator
from models.http import HttpResponseData, RequestData

from .client import HttpClient


class HeaderMutatingHttpClient(HttpClient):
    """Delegate to an inner :class:`HttpClient` after mutating headers.

    Composes like any other transport adapter: callers depend only on
    :class:`HttpClient`. Each configured mutator runs in order and its
    headers are merged over the request's own, so a mutator can override a
    specific header (e.g. ``User-Agent``) without disturbing the rest.
    """

    def __init__(self, inner: HttpClient, mutators: tuple[HeaderMutator, ...]) -> None:
        self._inner = inner
        self._mutators = mutators

    def send(self, request: RequestData) -> HttpResponseData:
        headers = dict(request.headers)
        for mutator in self._mutators:
            headers.update(mutator.headers_for_request())
        mutated = RequestData(
            url=request.url,
            method=request.method,
            headers=headers,
            cookies=request.cookies,
            query=request.query,
            body=request.body,
        )
        return self._inner.send(mutated)
