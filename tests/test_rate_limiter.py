"""Unit tests for the thread-safe request-rate limiter."""

import unittest

from core.rate_limiter import RateLimiter


class FakeClock:
    """A controllable monotonic clock for deterministic rate-limit tests."""

    def __init__(self, start: float = 0.0) -> None:
        self._now = start

    def advance(self, seconds: float) -> None:
        self._now += seconds

    def __call__(self) -> float:
        return self._now


class RateLimiterTests(unittest.TestCase):
    def test_unlimited_rate_never_sleeps(self) -> None:
        waited: list[float] = []
        limiter = RateLimiter(None, sleeper=waited.append)

        for _ in range(5):
            limiter.acquire()

        self.assertEqual(waited, [])

    def test_first_acquire_never_waits(self) -> None:
        waited: list[float] = []
        clock = FakeClock()
        limiter = RateLimiter(2.0, sleeper=waited.append, clock=clock)

        limiter.acquire()

        self.assertEqual(waited, [])

    def test_enforces_minimum_interval_between_acquisitions(self) -> None:
        waited: list[float] = []
        clock = FakeClock()

        def sleeper(seconds: float) -> None:
            waited.append(seconds)
            clock.advance(seconds)

        limiter = RateLimiter(2.0, sleeper=sleeper, clock=clock)  # 0.5s between calls

        limiter.acquire()
        limiter.acquire()  # called immediately: must wait ~0.5s
        self.assertEqual(waited, [0.5])

        clock.advance(0.5)  # caller "did work" for exactly the required gap
        limiter.acquire()  # already spaced out: no extra wait
        self.assertEqual(waited, [0.5])

    def test_rejects_non_positive_rate(self) -> None:
        with self.assertRaises(ValueError):
            RateLimiter(0)
        with self.assertRaises(ValueError):
            RateLimiter(-1.0)

    def test_max_per_second_round_trips(self) -> None:
        self.assertIsNone(RateLimiter(None).max_per_second)
        self.assertAlmostEqual(RateLimiter(4.0).max_per_second, 4.0)


if __name__ == "__main__":
    unittest.main()
