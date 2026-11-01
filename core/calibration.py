"""Automatic timing-baseline calibration for the time-based technique."""

import logging
import statistics
import time
from collections.abc import Callable

from models.http import RequestData
from payloads import InjectionPoint, PayloadBuilder
from transport import HttpClient


logger = logging.getLogger(__name__)


class TimingCalibrator:
    """Measure real response latency before trusting a timing threshold.

    Sends the FALSE branch of the real time-based payload (so no SLEEP is
    triggered) through the exact same client/injection point/payload builder
    that the attack will use, and reports the mean and population standard
    deviation of the observed latency. The caller decides how to turn those
    two numbers into ``baseline_seconds``/``tolerance_seconds``.
    """

    def __init__(
        self,
        *,
        http_client: HttpClient,
        injection_point: InjectionPoint,
        payload_builder: PayloadBuilder,
        base_request: RequestData,
        false_condition: str = "1=2",
        delay: float = 0.0,
        sleeper: Callable[[float], None] = time.sleep,
        sleep_seconds: float = 0.0,
        warmup: bool = True,
        jitter_threshold: float = 0.5,
    ) -> None:
        if not false_condition.strip():
            raise ValueError("false_condition cannot be empty")
        if delay < 0:
            raise ValueError("delay cannot be negative")
        self._http_client = http_client
        self._injection_point = injection_point
        self._payload_builder = payload_builder
        self._base_request = base_request
        self._false_condition = false_condition
        self._delay = delay
        self._sleeper = sleeper
        self._sleep_seconds = sleep_seconds
        self._warmup = warmup
        self._jitter_threshold = jitter_threshold
        self._last_mean: float | None = None
        self._last_stdev: float | None = None

    def _build_request(self) -> RequestData:
        payload = self._payload_builder.build(self._false_condition)
        return self._injection_point.inject(self._base_request, payload)

    def _send_one(self, request: RequestData) -> float:
        response = self._http_client.send(request)
        if self._delay:
            self._sleeper(self._delay)
        return response.elapsed_seconds

    def calibrate(self, samples: int) -> tuple[float, float]:
        """Return ``(mean_seconds, stdev_seconds)`` over ``samples`` requests."""
        if samples < 1:
            raise ValueError("samples must be positive")

        request = self._build_request()

        if self._warmup:
            self._http_client.send(request)
            if self._delay:
                self._sleeper(self._delay)
            logger.debug("Warmup request sent (result discarded)")

        elapsed: list[float] = []
        for index in range(samples):
            t = self._send_one(request)
            elapsed.append(t)
            logger.debug("Calibration sample %d/%d: %.4fs", index + 1, samples, t)

        mean = statistics.mean(elapsed)
        stdev = statistics.pstdev(elapsed) if len(elapsed) > 1 else 0.0

        if self._sleep_seconds > 0 and stdev / self._sleep_seconds > self._jitter_threshold:
            logger.warning(
                "High timing jitter detected: stdev=%.4fs is %.1f%% of sleep=%.4fs. "
                "Time-based detection may be unreliable.",
                stdev,
                (stdev / self._sleep_seconds) * 100,
                self._sleep_seconds,
            )

        self._last_mean = mean
        self._last_stdev = stdev

        logger.info(
            "Timing calibration: mean=%.4fs stdev=%.4fs over %d sample(s)",
            mean,
            stdev,
            samples,
        )
        return mean, stdev

    def quick_recalibrate(self, samples: int = 3) -> tuple[float, float]:
        """Fast recalibration with fewer samples and no warmup.

        Returns (mean, stdev). If a previous calibration exists, logs a
        warning when the new mean deviates significantly from the old one.
        """
        if samples < 1:
            raise ValueError("samples must be positive")

        request = self._build_request()
        elapsed: list[float] = []
        for index in range(samples):
            t = self._send_one(request)
            elapsed.append(t)
            logger.debug("Recalibration sample %d/%d: %.4fs", index + 1, samples, t)

        mean = statistics.mean(elapsed)
        stdev = statistics.pstdev(elapsed) if len(elapsed) > 1 else 0.0

        if self._last_mean is not None and self._last_stdev is not None:
            drift = abs(mean - self._last_mean)
            if self._last_stdev > 0 and drift > 2 * self._last_stdev:
                logger.warning(
                    "Timing baseline shifted: was %.4fs, now %.4fs (drift=%.4fs > 2*stdev=%.4fs). "
                    "Consider adjusting the threshold.",
                    self._last_mean,
                    mean,
                    drift,
                    2 * self._last_stdev,
                )

        self._last_mean = mean
        self._last_stdev = stdev

        logger.info(
            "Quick recalibration: mean=%.4fs stdev=%.4fs over %d sample(s)",
            mean,
            stdev,
            samples,
        )
        return mean, stdev
