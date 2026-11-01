"""Boolean-based SQL payload builders."""

from dataclasses import dataclass

from .contracts import PayloadBuilder


@dataclass(frozen=True, slots=True)
class BooleanPayloadBuilder(PayloadBuilder):
    """Wrap a condition with configurable boolean injection delimiters."""

    prefix: str = "' AND ("
    # Trailing space after -- is required by MySQL; harmless for PostgreSQL/Oracle.
    suffix: str = ")-- "

    def __post_init__(self) -> None:
        if not self.prefix:
            raise ValueError("prefix cannot be empty")
        if not self.suffix:
            raise ValueError("suffix cannot be empty")

    def build(self, condition: str) -> str:
        if not condition.strip():
            raise ValueError("condition cannot be empty")
        return f"{self.prefix}{condition}{self.suffix}"