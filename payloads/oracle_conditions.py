"""Oracle-specific SQL condition builders."""

from dataclasses import dataclass

from .conditions import _ALLOWED_OPERATORS
from .contracts import ConditionBuilder


@dataclass(frozen=True, slots=True)
class OracleAsciiSubstringConditionBuilder(ConditionBuilder):
    """Build ``ASCII(SUBSTR(expression, position, 1))`` comparisons."""

    substring_function: str = "SUBSTR"

    def __post_init__(self) -> None:
        if self.substring_function not in {"SUBSTR", "SUBSTRING"}:
            raise ValueError("substring_function must be SUBSTR or SUBSTRING")

    def build(self, expression: str, position: int, operator: str, value: int) -> str:
        if not expression.strip():
            raise ValueError("expression cannot be empty")
        if position < 1:
            raise ValueError("position must be positive")
        if operator not in _ALLOWED_OPERATORS:
            raise ValueError(f"Unsupported comparison operator: {operator}")
        if not isinstance(value, int) or isinstance(value, bool):
            raise TypeError("value must be an integer")
        return f"ASCII({self.substring_function}({expression},{position},1)){operator}{value}"