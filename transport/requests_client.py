"""`requests` adapter for the transport boundary."""

from time import perf_counter

import requests
from requests.adapters import HTTPAdapter
from urllib3.util.retry import Retry

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
        allow_redirects: bool = False,
        max_retries: int = 0,
        retry_backoff: float = 0.0,
        session: requests.Session | None = None,
    ) -> None:
        if timeout <= 0:
            raise ValueError("timeout must be greater than zero")
        if max_retries < 0:
            raise ValueError("max_retries cannot be negative")
        if retry_backoff < 0:
            raise ValueError("retry_backoff cannot be negative")
        self._timeout = timeout
        self._verify_ssl = verify_ssl
        self._proxy = proxy
        self._allow_redirects = allow_redirects
        self._session = session or requests.Session()
        retry = Retry(
            total=max_retries,
            connect=max_retries,
            read=max_retries,
            status=max_retries,
            backoff_factor=retry_backoff,
            status_forcelist=(429, 500, 502, 503, 504),
            allowed_methods=frozenset({"GET", "HEAD", "OPTIONS"}),
            raise_on_status=False,
        )
        adapter = HTTPAdapter(max_retries=retry)
        self._session.mount("http://", adapter)
        self._session.mount("https://", adapter)

    def send(self, request: RequestData) -> HttpResponseData:
        """Send a request and normalize its response, hiding Requests types."""
        proxies = {"http": self._proxy, "https": self._proxy} if self._proxy else None
        started = perf_counter()
        try:
            response = self._session.request(
                method=request.method,
                url=request.url,
                headers=dict(request.headers),
                cookies=dict(request.cookies),
                params=dict(request.query),
                data=dict(request.body) if request.method == "POST" else None,
                timeout=self._timeout,
                verify=self._verify_ssl,
                proxies=proxies,
                allow_redirects=self._allow_redirects,
            )
        except requests.RequestException as error:
            raise HttpRequestError(request.url, error) from error

        return HttpResponseData(
            status_code=response.status_code,
            text=response.text,
            headers=dict(response.headers),
            elapsed_seconds=perf_counter() - started,
        )