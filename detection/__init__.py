"""Response detection strategies."""

from .contracts import Detector
from .error import ErrorDetector
from .length import LengthDetector
from .status import StatusCodeDetector
from .text import TextDetector

__all__ = ["Detector", "ErrorDetector", "LengthDetector", "StatusCodeDetector", "TextDetector"]
