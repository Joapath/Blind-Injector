"""Unit tests for the canned enumeration catalog (cli/enum_catalog.py)."""

import unittest

from cli.enum_catalog import (
    AVAILABLE_KINDS,
    DUMP_EXTRA_CHARS,
    LIST_EXTRA_CHARS,
    LIST_KINDS,
    ROW_SEPARATOR,
    build_enum_expression,
    build_row_expression,
)

_DIALECTS = ("mysql", "postgres", "oracle")
_SCALAR_KINDS = ("current-db", "current-user", "version")


class EnumCatalogBasicTests(unittest.TestCase):
    def test_every_scalar_kind_builds_for_every_dialect(self) -> None:
        for kind in _SCALAR_KINDS:
            for dialect in _DIALECTS:
                expression = build_enum_expression(kind, dialect)
                self.assertTrue(expression.startswith("(SELECT"), f"{kind}/{dialect}")
                self.assertTrue(expression.endswith(")"), f"{kind}/{dialect}")

    def test_every_list_kind_builds_for_every_dialect(self) -> None:
        for kind in LIST_KINDS:
            for dialect in _DIALECTS:
                kwargs = {}
                if kind == "columns":
                    kwargs["table"] = "users"
                expression = build_enum_expression(kind, dialect, **kwargs)
                self.assertTrue(expression.startswith("(SELECT"), f"{kind}/{dialect}")
                self.assertTrue(expression.endswith(")"), f"{kind}/{dialect}")

    def test_columns_builds_for_every_dialect_with_table(self) -> None:
        for dialect in _DIALECTS:
            expression = build_enum_expression("columns", dialect, table="users")
            self.assertIn("column", expression.lower())

    def test_columns_requires_table(self) -> None:
        with self.assertRaises(ValueError):
            build_enum_expression("columns", "mysql")
        with self.assertRaises(ValueError):
            build_enum_expression("columns", "mysql", table="   ")

    def test_oracle_columns_upper_cases_table_name(self) -> None:
        expression = build_enum_expression("columns", "oracle", table="users")
        self.assertIn("table_name='USERS'", expression)

    def test_non_oracle_columns_keeps_table_case(self) -> None:
        expression = build_enum_expression("columns", "mysql", table="Users")
        self.assertIn("table_name='Users'", expression)

    def test_unknown_kind_raises(self) -> None:
        with self.assertRaises(ValueError):
            build_enum_expression("passwords", "mysql")

    def test_uncatalogued_dialect_raises(self) -> None:
        with self.assertRaises(ValueError):
            build_enum_expression("version", "mssql")


class CurrentDbTests(unittest.TestCase):
    def test_mysql_current_db(self) -> None:
        expr = build_enum_expression("current-db", "mysql")
        self.assertIn("DATABASE()", expr)

    def test_postgres_current_db(self) -> None:
        expr = build_enum_expression("current-db", "postgres")
        self.assertIn("current_database()", expr)

    def test_oracle_current_db(self) -> None:
        expr = build_enum_expression("current-db", "oracle")
        self.assertIn("SYS_CONTEXT", expr)
        self.assertIn("CURRENT_SCHEMA", expr)


class CountTests(unittest.TestCase):
    def test_count_requires_table(self) -> None:
        with self.assertRaises(ValueError):
            build_enum_expression("count", "mysql")
        with self.assertRaises(ValueError):
            build_enum_expression("count", "mysql", table="  ")

    def test_count_mysql(self) -> None:
        expr = build_enum_expression("count", "mysql", table="users")
        self.assertIn("COUNT(*)", expr)
        self.assertIn("users", expr)

    def test_count_postgres(self) -> None:
        expr = build_enum_expression("count", "postgres", table="users")
        self.assertIn("COUNT(*)", expr)
        self.assertIn("users", expr)

    def test_count_oracle_uppercases_table(self) -> None:
        expr = build_enum_expression("count", "oracle", table="users")
        self.assertIn("COUNT(*)", expr)
        self.assertIn("USERS", expr)

    def test_count_with_database_qualifies_table(self) -> None:
        expr = build_enum_expression("count", "mysql", table="users", database="mydb")
        self.assertIn("mydb.users", expr)

    def test_count_without_database_uses_bare_table(self) -> None:
        expr = build_enum_expression("count", "postgres", table="users")
        self.assertIn("FROM users", expr)
        self.assertNotIn(".", expr.split("FROM")[1].split(")")[0])


class DatabaseScopeTests(unittest.TestCase):
    """Tests for -D (database) scoping on tables and columns."""

    def test_tables_mysql_default_uses_database_func(self) -> None:
        expr = build_enum_expression("tables", "mysql")
        self.assertIn("DATABASE()", expr)

    def test_tables_mysql_with_database(self) -> None:
        expr = build_enum_expression("tables", "mysql", database="mydb")
        self.assertIn("'mydb'", expr)
        self.assertNotIn("DATABASE()", expr)

    def test_tables_postgres_default_uses_public(self) -> None:
        expr = build_enum_expression("tables", "postgres")
        self.assertIn("'public'", expr)

    def test_tables_postgres_with_database(self) -> None:
        expr = build_enum_expression("tables", "postgres", database="myschema")
        self.assertIn("'myschema'", expr)

    def test_tables_oracle_default_uses_user(self) -> None:
        expr = build_enum_expression("tables", "oracle")
        self.assertIn("USER", expr)

    def test_tables_oracle_with_database(self) -> None:
        expr = build_enum_expression("tables", "oracle", database="ADMIN")
        self.assertIn("UPPER('ADMIN')", expr)

    def test_columns_mysql_with_database(self) -> None:
        expr = build_enum_expression("columns", "mysql", table="users", database="mydb")
        self.assertIn("table_name='users'", expr)
        self.assertIn("table_schema='mydb'", expr)

    def test_columns_mysql_without_database(self) -> None:
        expr = build_enum_expression("columns", "mysql", table="users")
        self.assertIn("table_name='users'", expr)
        self.assertIn("table_schema=DATABASE()", expr)

    def test_columns_postgres_with_database(self) -> None:
        expr = build_enum_expression("columns", "postgres", table="users", database="myschema")
        self.assertIn("table_name='users'", expr)
        self.assertIn("table_schema='myschema'", expr)

    def test_columns_postgres_without_database(self) -> None:
        expr = build_enum_expression("columns", "postgres", table="users")
        self.assertIn("table_name='users'", expr)
        self.assertIn("table_schema='public'", expr)

    def test_columns_oracle_with_database(self) -> None:
        expr = build_enum_expression("columns", "oracle", table="users", database="ADMIN")
        self.assertIn("table_name='USERS'", expr)
        self.assertIn("owner=UPPER('ADMIN')", expr)

    def test_columns_oracle_without_database(self) -> None:
        expr = build_enum_expression("columns", "oracle", table="users")
        self.assertIn("table_name='USERS'", expr)
        self.assertIn("owner=USER", expr)


class BuildRowExpressionTests(unittest.TestCase):
    def test_mysql_single_column(self) -> None:
        expr = build_row_expression("mysql", ["id"], table="users", offset=0)
        self.assertIn("CONCAT_WS", expr)
        self.assertIn("COALESCE", expr)
        self.assertIn("LIMIT 1 OFFSET 0", expr)

    def test_mysql_multiple_columns(self) -> None:
        expr = build_row_expression(
            "mysql", ["id", "name", "email"], table="users", offset=3
        )
        self.assertIn("CONCAT_WS", expr)
        self.assertEqual(expr.count("COALESCE"), 3)
        self.assertIn("OFFSET 3", expr)

    def test_postgres_single_column(self) -> None:
        expr = build_row_expression("postgres", ["id"], table="users", offset=0)
        self.assertIn('"id"::text', expr)
        self.assertIn("LIMIT 1 OFFSET 0", expr)

    def test_postgres_multiple_columns_uses_separator(self) -> None:
        expr = build_row_expression(
            "postgres", ["id", "name"], table="users", offset=0
        )
        self.assertIn(ROW_SEPARATOR, expr)
        self.assertEqual(expr.count("COALESCE"), 2)
        self.assertIn('"id"', expr)
        self.assertIn('"name"', expr)

    def test_oracle_uses_rownum(self) -> None:
        expr = build_row_expression("oracle", ["id", "name"], table="users", offset=0)
        self.assertIn("ROWNUM", expr)
        self.assertIn("rn=1", expr)

    def test_oracle_offset_is_one_based(self) -> None:
        expr = build_row_expression("oracle", ["id"], table="users", offset=5)
        self.assertIn("rn=6", expr)

    def test_oracle_uppercases_table(self) -> None:
        expr = build_row_expression("oracle", ["id"], table="users", offset=0)
        self.assertIn("USERS", expr)

    def test_with_database_qualifies_table(self) -> None:
        expr = build_row_expression(
            "mysql", ["id"], table="users", database="mydb", offset=0
        )
        self.assertIn("mydb.users", expr)

    def test_without_database_uses_bare_table(self) -> None:
        expr = build_row_expression("mysql", ["id"], table="users", offset=0)
        self.assertIn("FROM users", expr)
        self.assertNotIn(".", expr.split("FROM")[1].split(" ")[1])

    def test_empty_columns_raises(self) -> None:
        with self.assertRaises(ValueError):
            build_row_expression("mysql", [], table="users", offset=0)

    def test_no_table_raises(self) -> None:
        with self.assertRaises(ValueError):
            build_row_expression("mysql", ["id"], table="", offset=0)
        with self.assertRaises(ValueError):
            build_row_expression("mysql", ["id"], table="  ", offset=0)

    def test_negative_offset_raises(self) -> None:
        with self.assertRaises(ValueError):
            build_row_expression("mysql", ["id"], table="users", offset=-1)

    def test_unsupported_dialect_raises(self) -> None:
        with self.assertRaises(ValueError):
            build_row_expression("mssql", ["id"], table="users", offset=0)

    def test_null_handling_in_all_dialects(self) -> None:
        for dialect in _DIALECTS:
            expr = build_row_expression(dialect, ["col1"], table="t", offset=0)
            self.assertIn("COALESCE", expr)
            self.assertIn("NULL", expr)


class ConstantsTests(unittest.TestCase):
    def test_available_kinds_sorted(self) -> None:
        self.assertEqual(AVAILABLE_KINDS, tuple(sorted(AVAILABLE_KINDS)))

    def test_list_kinds_are_subset_of_available(self) -> None:
        for kind in LIST_KINDS:
            self.assertIn(kind, AVAILABLE_KINDS)

    def test_dump_extra_chars_contains_separator(self) -> None:
        self.assertIn(ROW_SEPARATOR, DUMP_EXTRA_CHARS)

    def test_row_separator_is_section_sign(self) -> None:
        self.assertEqual(ROW_SEPARATOR, "§")

    def test_dump_extra_chars_has_uppercase_and_digits(self) -> None:
        for c in "ABCXYZ":
            self.assertIn(c, DUMP_EXTRA_CHARS)
        for c in "0129":
            self.assertIn(c, DUMP_EXTRA_CHARS)

    def test_current_db_not_in_list_kinds(self) -> None:
        self.assertNotIn("current-db", LIST_KINDS)

    def test_count_not_in_list_kinds(self) -> None:
        self.assertNotIn("count", LIST_KINDS)


if __name__ == "__main__":
    unittest.main()
