"""HTTP client contract."""

from abc import ABC, abstractmethod

from models.http import HttpResponseData, RequestData


class HttpClient(ABC):
    """Transport boundary used by the extraction core."""

    @abstractmethod
    def send(self, request: RequestData) -> HttpResponseData:
        """Send a request and return a normalized response."""
        raise NotImplementedError