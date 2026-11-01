"""HttpClient decorator that applies a rate limit before delegating."""

from core.rate_limiter import RateLimiter
from models.http import HttpResponseData, RequestData

from .client import HttpClient


class RateLimitedHttpClient(HttpClient):
    """Delegate to an inner :class:`HttpClient` after acquiring a rate slot.

    Composes like any other transport adapter: callers depend only on
    :class:`HttpClient`, so wrapping a client with a rate limit never has to
    be known by detectors, extractors, or techniques.
    """

    def __init__(self, inner: HttpClient, limiter: RateLimiter) -> None:
        self._inner = inner
        self._limiter = limiter

    def send(self, request: RequestData) -> HttpResponseData:
        self._limiter.acquire()
        return self._inner.send(request)
