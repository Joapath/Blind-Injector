"""Target and attack configuration data models."""

from dataclasses import dataclass, field
from types import MappingProxyType
from typing import Mapping
from urllib.parse import urlparse


_ALLOWED_METHODS = frozenset({"GET", "POST"})


@dataclass(frozen=True, slots=True)
class Target:
    """Base target request information."""

    url: str
    method: str = "GET"
    headers: Mapping[str, str] = field(default_factory=dict)
    cookies: Mapping[str, str] = field(default_factory=dict)
    query: Mapping[str, str] = field(default_factory=dict)
    body: Mapping[str, str] = field(default_factory=dict)

    def __post_init__(self) -> None:
        method = self.method.upper()
        if method not in _ALLOWED_METHODS:
            raise ValueError(f"Unsupported HTTP method: {self.method}")
        if not urlparse(self.url).scheme or not urlparse(self.url).netloc:
            raise ValueError("Target URL must include a scheme and host")
        object.__setattr__(self, "method", method)
        for name in ("headers", "cookies", "query", "body"):
            object.__setattr__(self, name, MappingProxyType(dict(getattr(self, name))))


@dataclass(frozen=True, slots=True)
class AttackConfiguration:
    """Immutable values controlling one extraction run."""

    target: Target
    charset: str = "abcdefghijklmnopqrstuvwxyz0123456789"
    timeout: float = 10.0
    verify_ssl: bool = True
    proxy: str | None = None
    allow_redirects: bool = False
    max_retries: int = 0
    retry_backoff: float = 0.0
    delay: float = 0.0
    parameter: str = ""
    injection_location: str = "query"
    injection_mode: str = "append"
    strategy: str = "binary"
    detector: str = "text"
    detector_value: str = ""
    expected_length: int | None = None
    expected_status: int | None = None
    max_length: int = 100
    attack_mode: str = "conditional-response"
    dialect: str = "oracle"
    technique: str = "boolean"
    sleep_seconds: float | None = None
    timing_threshold: float | None = None
    timing_baseline: float = 0.0
    timing_tolerance: float = 0.0
    table: str = "users"
    column: str = "password"
    user_column: str = "username"
    username: str = "administrator"
    error_text: str | None = None
    error_regex: str | None = None
    error_value_regex: str | None = None
    error_status: int | None = None
    auto_calibrate: bool = False
    calibration_samples: int = 5
    calibration_tolerance_factor: float = 3.0
    rate_limit: float | None = None
    max_workers: int = 1
    resume: bool = False
    checkpoint_dir: str | None = None
    tampers: tuple[str, ...] = ()
    random_agent: bool = False
    random_forwarded_for: bool = False

    def __post_init__(self) -> None:
        if not self.charset:
            raise ValueError("charset cannot be empty")
        if self.timeout <= 0:
            raise ValueError("timeout must be greater than zero")
        if self.delay < 0:
            raise ValueError("delay cannot be negative")
        if self.max_retries < 0:
            raise ValueError("max_retries cannot be negative")
        if self.retry_backoff < 0:
            raise ValueError("retry_backoff cannot be negative")
        if not self.parameter:
            raise ValueError("parameter cannot be empty")
        if self.injection_location not in {"query", "body", "cookie"}:
            raise ValueError("injection_location must be query, body, or cookie")
        if self.injection_mode not in {"append", "replace"}:
            raise ValueError("injection_mode must be append or replace")
        if self.strategy not in {"brute", "binary"}:
            raise ValueError("strategy must be brute or binary")
        if self.technique not in {"boolean", "time", "visible-error", "auto"}:
            raise ValueError("technique must be boolean, time, visible-error, or auto")
        if self.detector not in {"text", "length", "status", "error", "timing"}:
            raise ValueError("detector must be text, length, status, error, or timing")
        if self.attack_mode not in {
            "conditional-response",
            "conditional-error",
            "visible-error",
        }:
            raise ValueError(
                "attack_mode must be conditional-response, conditional-error, or visible-error"
            )
        if not self.dialect:
            raise ValueError("dialect cannot be empty")
        for name in ("table", "column", "user_column", "username"):
            if not getattr(self, name).strip():
                raise ValueError(f"{name} cannot be empty")

        if self.calibration_samples < 1:
            raise ValueError("calibration_samples must be positive")
        if self.calibration_tolerance_factor <= 0:
            raise ValueError("calibration_tolerance_factor must be greater than zero")
        if self.rate_limit is not None and self.rate_limit <= 0:
            raise ValueError("rate_limit must be greater than zero")
        if self.max_workers < 1:
            raise ValueError("max_workers must be positive")
        if self.max_workers > 1 and self.technique == "time":
            raise ValueError(
                "max_workers greater than 1 is not supported for technique=time: "
                "concurrent requests would skew timing measurements"
            )
        if self.max_length < 1:
            raise ValueError("max_length must be positive")

        if self.technique == "auto":
            # Nothing technique-specific is known yet -- fingerprinting (see
            # config.fingerprint) decides it. Only the generic request/
            # extraction fields validated above apply.
            return

        if self.technique == "visible-error":
            if self.attack_mode != "visible-error":
                raise ValueError("visible-error technique requires visible-error attack mode")
            if self.dialect != "postgres":
                raise ValueError("visible-error currently supports only the postgres dialect")
            if self.detector != "error":
                raise ValueError("visible-error technique requires the error detector")
            return

        if self.attack_mode == "visible-error":
            raise ValueError("visible-error attack mode requires technique=visible-error")

        if self.technique == "time":
            if self.attack_mode != "conditional-response":
                raise ValueError("time-based attacks require conditional-response attack mode")
            if self.dialect not in {"mysql", "postgres"}:
                raise ValueError("time-based attacks currently support the mysql or postgres dialects")
            if self.sleep_seconds is None or self.sleep_seconds <= 0:
                raise ValueError("sleep_seconds is required for time-based techniques")
            if self.timing_threshold is None or self.timing_threshold <= 0:
                raise ValueError("timing_threshold is required for time-based techniques")
            if self.timing_threshold > self.sleep_seconds:
                raise ValueError("timing_threshold cannot exceed sleep_seconds")
            if self.timing_baseline < 0:
                raise ValueError("timing_baseline cannot be negative")
            if self.timing_tolerance < 0:
                raise ValueError("timing_tolerance cannot be negative")

            boolean_signal_present = bool(
                self.detector_value
                or self.expected_length is not None
                or self.expected_status is not None
                or self.error_text is not None
                or self.error_regex is not None
                or self.error_status is not None
            )
            if self.detector == "text" and not boolean_signal_present:
                object.__setattr__(self, "detector", "timing")
                return
            if self.detector in {"length", "status", "error", "text"}:
                raise ValueError("time-based techniques do not support boolean-style detectors")
            if self.detector != "timing":
                raise ValueError("time-based techniques require a timing-compatible detector")
            return

        if self.detector == "timing":
            raise ValueError("timing detector is only valid for technique=time")

        if self.attack_mode == "conditional-response" and self.detector == "error":
            raise ValueError("error detector requires conditional-error attack mode")

        error_mode = self.attack_mode == "conditional-error"
        if error_mode:
            if self.dialect != "oracle":
                raise ValueError("conditional-error currently supports only the oracle dialect")
            if not any((self.error_text, self.error_regex, self.error_status is not None, self.detector_value)):
                raise ValueError("conditional-error requires error text, regex, or status")
            if self.error_status is not None and not 100 <= self.error_status <= 599:
                raise ValueError("error_status must be between 100 and 599")
        elif self.detector == "text" and not self.detector_value:
            raise ValueError("detector_value is required for text and error detection")
        if self.detector == "length":
            if self.expected_length is None or self.expected_length < 0:
                raise ValueError("expected_length is required for length detection")
        if self.detector == "status":
            if self.expected_status is None or not 100 <= self.expected_status <= 599:
                raise ValueError("expected_status is required for status detection")
