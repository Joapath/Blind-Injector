"""Concrete SQL condition builders."""

from dataclasses import dataclass

from .contracts import ConditionBuilder


_ALLOWED_OPERATORS = frozenset({"=", ">", ">=", "<", "<=", "<>"})


@dataclass(frozen=True, slots=True)
class AsciiSubstringConditionBuilder(ConditionBuilder):
    """Build an ASCII comparison for one character of a SQL expression."""

    def build(self, expression: str, position: int, operator: str, value: int) -> str:
        if not expression.strip():
            raise ValueError("expression cannot be empty")
        if position < 1:
            raise ValueError("position must be positive")
        if operator not in _ALLOWED_OPERATORS:
            raise ValueError(f"Unsupported comparison operator: {operator}")
        if not isinstance(value, int) or isinstance(value, bool):
            raise TypeError("value must be an integer")

        return f"ASCII(SUBSTRING({expression},{position},1)){operator}{value}"

    def build_length(self, expression: str, position: int, operator: str = "<") -> str:
        if not expression.strip():
            raise ValueError("expression cannot be empty")
        if position < 1:
            raise ValueError("position must be positive")
        if operator not in _ALLOWED_OPERATORS:
            raise ValueError(f"Unsupported comparison operator: {operator}")
        return f"LENGTH({expression}){operator}{position}"