"""`requests` adapter for the transport boundary."""

from time import perf_counter

import requests

from exceptions import HttpRequestError
from models.http import HttpResponseData, RequestData

from .client import HttpClient


class RequestsHttpClient(HttpClient):
    """Send normalized requests through the Requests library."""

    def __init__(
        self,
        *,
        timeout: float = 10.0,
        verify_ssl: bool = True,
        proxy: str | None = None,
    ) -> None:
        if timeout <= 0:
            raise ValueError("timeout must be greater than zero")
        self._timeout = timeout
        self._verify_ssl = verify_ssl
        self._proxy = proxy

    def send(self, request: RequestData) -> HttpResponseData:
        """Send a request and normalize its response, hiding Requests types."""
        proxies = {"http": self._proxy, "https": self._proxy} if self._proxy else None
        started = perf_counter()
        try:
            response = requests.request(
                method=request.method,
                url=request.url,
                headers=dict(request.headers),
                cookies=dict(request.cookies),
                params=dict(request.query),
                data=dict(request.body) if request.method == "POST" else None,
                timeout=self._timeout,
                verify=self._verify_ssl,
                proxies=proxies,
            )
        except requests.RequestException as error:
            raise HttpRequestError(request.url, error) from error

        return HttpResponseData(
            status_code=response.status_code,
            text=response.text,
            headers=dict(response.headers),
            elapsed_seconds=perf_counter() - started,
        )