"""Project-specific exceptions."""


class BlindFinderError(Exception):
    """Base exception for expected framework errors."""


class HttpRequestError(BlindFinderError):
    """A request could not be completed by the configured HTTP client."""

    def __init__(self, url: str, cause: Exception) -> None:
        super().__init__("HTTP request failed")
        self.url = url
        self.cause = cause