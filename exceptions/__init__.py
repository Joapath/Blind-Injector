"""Project-specific exceptions."""


class BlindFinderError(Exception):
    """Base exception for expected framework errors."""


class HttpRequestError(BlindFinderError):
    """A request could not be completed by the configured HTTP client."""

    def __init__(self, url: str, cause: Exception) -> None:
        super().__init__("HTTP request failed")
        self.url = url
        self.cause = cause


class CheckpointError(BlindFinderError):
    """A checkpoint file could not be read, written, or parsed."""

    def __init__(self, path: str, cause: Exception) -> None:
        super().__init__("Checkpoint could not be processed")
        self.path = path
        self.cause = cause