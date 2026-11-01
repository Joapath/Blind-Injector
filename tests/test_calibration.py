"""Unit tests for automatic timing-baseline calibration."""

import unittest

from core.calibration import TimingCalibrator
from models import HttpResponseData, RequestData
from payloads import QueryParameterInjectionPoint, TimePayloadBuilder
from transport import HttpClient


class ScriptedHttpClient(HttpClient):
    """Return a fixed, deterministic sequence of elapsed times."""

    def __init__(self, elapsed_seconds: list[float]) -> None:
        self._elapsed = list(elapsed_seconds)
        self.requests = []

    def send(self, request: RequestData) -> HttpResponseData:
        self.requests.append(request)
        elapsed = self._elapsed.pop(0)
        return HttpResponseData(200, "ok", elapsed_seconds=elapsed)


def build_calibrator(client: HttpClient, **kwargs) -> TimingCalibrator:
    return TimingCalibrator(
        http_client=client,
        injection_point=QueryParameterInjectionPoint("tracking"),
        payload_builder=TimePayloadBuilder(sleep_seconds=3.0),
        base_request=RequestData("https://example.test/filter", query={"tracking": "base"}),
        **kwargs,
    )


class TimingCalibratorTests(unittest.TestCase):
    def test_computes_mean_and_population_stdev_over_samples(self) -> None:
        # +1 warmup request
        client = ScriptedHttpClient([0.08, 0.10, 0.12, 0.11, 0.09, 0.13])
        calibrator = build_calibrator(client)

        mean, stdev = calibrator.calibrate(samples=5)

        self.assertAlmostEqual(mean, 0.11, places=6)
        self.assertGreater(stdev, 0.0)
        self.assertEqual(len(client.requests), 6)  # 1 warmup + 5 samples

    def test_single_sample_has_zero_stdev(self) -> None:
        client = ScriptedHttpClient([0.08, 0.5])  # warmup + 1 sample
        calibrator = build_calibrator(client)

        mean, stdev = calibrator.calibrate(samples=1)

        self.assertEqual(mean, 0.5)
        self.assertEqual(stdev, 0.0)

    def test_uses_the_false_branch_of_the_real_timing_payload(self) -> None:
        client = ScriptedHttpClient([0.05, 0.1, 0.1])  # warmup + 2
        calibrator = build_calibrator(client)

        calibrator.calibrate(samples=2)

        payload = client.requests[0].query["tracking"]
        self.assertIn("1=2", payload)
        self.assertIn("SLEEP(3.0)", payload)

    def test_rejects_non_positive_sample_count(self) -> None:
        client = ScriptedHttpClient([0.1])
        calibrator = build_calibrator(client)

        with self.assertRaises(ValueError):
            calibrator.calibrate(samples=0)

    def test_rejects_empty_false_condition(self) -> None:
        client = ScriptedHttpClient([])
        with self.assertRaises(ValueError):
            build_calibrator(client, false_condition="  ")

    def test_sleeps_between_samples_when_delay_configured(self) -> None:
        client = ScriptedHttpClient([0.05, 0.1, 0.1, 0.1])  # warmup + 3
        waited: list[float] = []
        calibrator = build_calibrator(client, delay=0.2, sleeper=waited.append)

        calibrator.calibrate(samples=3)

        # warmup delay + 3 sample delays = 4
        self.assertEqual(waited, [0.2, 0.2, 0.2, 0.2])

    def test_warmup_can_be_disabled(self) -> None:
        client = ScriptedHttpClient([0.10, 0.12])
        calibrator = build_calibrator(client, warmup=False)

        mean, _stdev = calibrator.calibrate(samples=2)

        self.assertAlmostEqual(mean, 0.11, places=6)
        self.assertEqual(len(client.requests), 2)  # no warmup

    def test_jitter_warning_logged_when_stdev_is_high(self) -> None:
        client = ScriptedHttpClient([0.05, 0.1, 2.0, 0.1])  # warmup + 3 (high variance)
        calibrator = build_calibrator(client, sleep_seconds=1.0)

        with self.assertLogs("core.calibration", level="WARNING") as logs:
            calibrator.calibrate(samples=3)

        joined = "\n".join(logs.output)
        self.assertIn("jitter", joined.lower())

    def test_no_jitter_warning_when_stdev_is_low(self) -> None:
        client = ScriptedHttpClient([0.05, 0.10, 0.11, 0.10])  # warmup + 3
        calibrator = build_calibrator(client, sleep_seconds=3.0)

        calibrator.calibrate(samples=3)
        # No assertLogs with WARNING; if it had logged a warning, this would be wrong

    def test_quick_recalibrate_returns_mean_and_stdev(self) -> None:
        # Warmup + 5 for calibrate, then 3 for quick_recalibrate
        client = ScriptedHttpClient([0.05, 0.1, 0.1, 0.1, 0.1, 0.1, 0.2, 0.2, 0.2])
        calibrator = build_calibrator(client)

        calibrator.calibrate(samples=5)
        mean, stdev = calibrator.quick_recalibrate(samples=3)

        self.assertAlmostEqual(mean, 0.2, places=6)
        self.assertEqual(stdev, 0.0)

    def test_quick_recalibrate_warns_on_drift(self) -> None:
        # Warmup + 3 for calibrate, then 3 for quick_recalibrate with drift
        client = ScriptedHttpClient([0.05, 0.1, 0.12, 0.11, 0.5, 0.5, 0.5])
        calibrator = build_calibrator(client)

        calibrator.calibrate(samples=3)

        with self.assertLogs("core.calibration", level="WARNING") as logs:
            calibrator.quick_recalibrate(samples=3)

        joined = "\n".join(logs.output)
        self.assertIn("shifted", joined.lower())


if __name__ == "__main__":
    unittest.main()
