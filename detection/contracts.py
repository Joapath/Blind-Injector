"""Response detector contract."""

from abc import ABC, abstractmethod

from models.http import HttpResponseData


class Detector(ABC):
    """Classify a normalized HTTP response as true or false."""

    @abstractmethod
    def is_true(self, response: HttpResponseData) -> bool:
        """Return whether the response represents a true condition."""
        raise NotImplementedError
