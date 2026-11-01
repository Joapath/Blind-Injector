"""Thread-safe request-rate limiting."""

import threading
import time
from collections.abc import Callable


class RateLimiter:
    """Bound the rate of an arbitrary action to at most ``max_per_second``.

    Implements a simple "minimum interval between acquisitions" limiter
    (not a bursting token bucket): each ``acquire()`` blocks just long enough
    so that calls are spaced at least ``1 / max_per_second`` seconds apart,
    measured from the previous acquisition. Safe to share one instance
    across multiple threads.

    ``clock``/``sleeper`` are injectable so tests can run deterministically
    without waiting on a real clock, mirroring the ``sleeper`` seam already
    used by :class:`core.extractor.BlindExtractor`.
    """

    def __init__(
        self,
        max_per_second: float | None,
        *,
        sleeper: Callable[[float], None] = time.sleep,
        clock: Callable[[], float] = time.monotonic,
    ) -> None:
        if max_per_second is not None and max_per_second <= 0:
            raise ValueError("max_per_second must be greater than zero")
        self._min_interval = 1.0 / max_per_second if max_per_second else 0.0
        self._sleeper = sleeper
        self._clock = clock
        self._lock = threading.Lock()
        self._next_allowed: float | None = None

    @property
    def max_per_second(self) -> float | None:
        """Return the configured rate, or ``None`` when unlimited."""
        return 1.0 / self._min_interval if self._min_interval else None

    def acquire(self) -> None:
        """Block, if necessary, until the configured rate allows proceeding."""
        if self._min_interval <= 0:
            return

        with self._lock:
            now = self._clock()
            wait = 0.0 if self._next_allowed is None else self._next_allowed - now
            if wait > 0:
                self._sleeper(wait)
                now += wait
            self._next_allowed = now + self._min_interval
