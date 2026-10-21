"""SQLite database layer (S3), tested below or without the AST gate.

SQLite has no grants, so ``SQLiteExecutor`` installs an authorizer built from the role policy.
These tests call the executor directly, or go through ``SecureSqlTool`` with ``GateMode.OFF``,
and check that the database alone refuses what the role may not read and every non-SELECT
action. The database is generated from the policy, so it never depends on db/security.
"""

import asyncio
import hashlib
import sqlite3

import pytest

from sqlguard.mcp.tools import ToolError
from sqlguard.security.audit import InMemoryAuditSink
from sqlguard.security.gate import GateMode, PolicySQLGate, SecurityContext
from sqlguard.security.policy import RolePolicy, load_default_policy
from sqlguard.security.service import ExecutorError, SecureSqlTool
from sqlguard.security.sqlite import SQLiteExecutor, has_unchecked_join

POLICY = load_default_policy()
ROLES = tuple(sorted(POLICY.roles))


@pytest.fixture
def db_path(tmp_path):
    path = tmp_path / "policy.sqlite"
    canaries = {(c.table, c.column): c.value for c in POLICY.canaries}
    with sqlite3.connect(path) as connection:
        for table, columns in sorted(POLICY.tables.items()):
            ordered = sorted(columns)
            connection.execute(f'CREATE TABLE "{table}" ({", ".join(ordered)})')
            for row in (1, 2):
                values = [canaries.get((table, c), f"{table}.{c}.{row}") for c in ordered]
                placeholders = ", ".join("?" for _ in ordered)
                connection.execute(f'INSERT INTO "{table}" VALUES ({placeholders})', values)
        connection.execute("CREATE TABLE secret_table (secret TEXT)")
        connection.execute("INSERT INTO secret_table VALUES ('CANARY-SECRET-0001')")
    connection.close()
    return path


def execute(path, role, sql, timeout=3.0, policy=POLICY):
    executor = SQLiteExecutor(path, policy)
    return asyncio.run(executor.execute(sql, role=role, timeout_seconds=timeout, max_rows=100))


def denied_category(path, role, sql):
    with pytest.raises(ExecutorError) as raised:
        execute(path, role, sql)
    return raised.value.category


def digest(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


def readable_table(role):
    return sorted(POLICY.allowed_tables(role))[0]


def forbidden_columns(role):
    return sorted(
        (table, column)
        for table, columns in POLICY.tables.items()
        for column in columns
        if not POLICY.can_read(role, table, column)
    )


def test_every_column_is_readable_exactly_when_the_policy_allows_it(db_path):
    for role in ROLES:
        for table, columns in POLICY.tables.items():
            for column in columns:
                sql = f'SELECT "{column}" FROM "{table}"'
                if POLICY.can_read(role, table, column):
                    assert len(execute(db_path, role, sql).rows) == 2, (role, table, column)
                else:
                    category = denied_category(db_path, role, sql)
                    assert category == "db_permission_denied", (role, table, column)


@pytest.mark.parametrize("role", ROLES)
def test_forbidden_columns_are_denied_anywhere_in_the_query(db_path, role):
    table, column = forbidden_columns(role)[0]
    allowed = sorted(POLICY.allowed_columns(role, table))
    visible = allowed[0] if allowed else "1"
    for sql in (
        f'SELECT * FROM "{table}"',
        f'SELECT {visible} FROM "{table}" WHERE "{column}" LIKE \'%\'',
        f'SELECT {visible} FROM "{table}" ORDER BY "{column}"',
        f'SELECT COUNT(DISTINCT "{column}") FROM "{table}"',
    ):
        assert denied_category(db_path, role, sql) == "db_permission_denied", sql


@pytest.mark.parametrize("role", ROLES)
@pytest.mark.parametrize(
    "sql",
    [
        "SELECT secret FROM secret_table",
        "SELECT COUNT(*) FROM secret_table",
        "SELECT name, sql FROM sqlite_master",
        "SELECT name FROM sqlite_schema",
        "SELECT name FROM sqlite_temp_master",
        "SELECT * FROM pragma_table_info('secret_table')",
        "SELECT name FROM pragma_table_list",
        "SELECT sqlite_version()",
        "SELECT load_extension('evil')",
        "SELECT length(randomblob(1000000000))",
        "SELECT length(zeroblob(1000000000))",
        "SELECT printf('%.*c', 1000000000, 'x')",
        "WITH RECURSIVE c(x) AS (SELECT 1 UNION ALL SELECT x + 1 FROM c) SELECT x FROM c",
        "PRAGMA table_info(secret_table)",
        "PRAGMA query_only = OFF",
    ],
)
def test_catalog_pragma_and_unlisted_functions_are_denied(db_path, role, sql):
    assert denied_category(db_path, role, sql) == "db_permission_denied"


@pytest.mark.parametrize("role", ROLES)
def test_writes_ddl_attach_and_vacuum_into_are_denied_and_leave_the_file_unchanged(
    db_path, tmp_path, role
):
    table = readable_table(role)
    column = sorted(POLICY.allowed_columns(role, table))[0]
    copy = tmp_path / "exfiltrated.sqlite"
    before = digest(db_path)
    for sql in (
        f'DELETE FROM "{table}"',
        f'UPDATE "{table}" SET "{column}" = NULL',
        f'INSERT INTO "{table}" ("{column}") VALUES (NULL)',
        f'DROP TABLE "{table}"',
        "CREATE TABLE stolen (a)",
        "CREATE TEMP TABLE stolen (a)",
        "CREATE TEMP VIEW stolen AS SELECT secret FROM secret_table",
        "ATTACH DATABASE ':memory:' AS side",
        f"VACUUM INTO '{copy.as_posix()}'",
        "BEGIN IMMEDIATE",
    ):
        assert denied_category(db_path, role, sql) == "db_permission_denied", sql

    # Without the authorizer VACUUM INTO still creates the target file on a mode=ro connection.
    assert not copy.exists()
    assert digest(db_path) == before


def test_multiple_statements_are_rejected_by_the_driver(db_path):
    table = readable_table("sales")
    sql = f'SELECT 1 FROM "{table}"; DELETE FROM "{table}"'

    assert denied_category(db_path, "sales", sql) == "db_syntax_error"
    assert len(execute(db_path, "sales", f'SELECT COUNT(*) FROM "{table}"').rows) == 1


@pytest.mark.parametrize("role", ROLES)
def test_allowed_queries_still_run(db_path, role):
    table = readable_table(role)
    column = sorted(POLICY.allowed_columns(role, table))[0]
    for sql in (
        f'SELECT COUNT(*) FROM "{table}"',
        f'SELECT "{column}" FROM "{table}" WHERE "{column}" LIKE \'%\'',
        f'SELECT LOWER("{column}"), UPPER("{column}"), LENGTH("{column}") FROM "{table}"',
        f'SELECT COALESCE("{column}", \'x\'), NULLIF("{column}", \'x\') FROM "{table}"',
        f'SELECT IIF("{column}" IS NULL, 0, 1), CAST("{column}" AS TEXT) FROM "{table}"',
        f'SELECT DISTINCT "{column}" FROM "{table}" ORDER BY "{column}" LIMIT 1',
        "SELECT CURRENT_DATE",
    ):
        assert execute(db_path, role, sql).rows, sql


def test_join_on_readable_foreign_key_runs(db_path):
    for pair in sorted(POLICY.foreign_keys, key=sorted):
        (left_table, left_column), (right_table, right_column) = sorted(pair)
        role = next(
            (
                role
                for role in ROLES
                if POLICY.can_read(role, left_table, left_column)
                and POLICY.can_read(role, right_table, right_column)
            ),
            None,
        )
        if role is None:
            continue
        sql = (
            f'SELECT l."{left_column}" FROM "{left_table}" l JOIN "{right_table}" r '
            f'ON l."{left_column}" = r."{right_column}"'
        )
        execute(db_path, role, sql)
        return
    pytest.skip("policy has no foreign key readable by a single role")


def test_unknown_role_is_refused_before_touching_the_database(db_path):
    assert denied_category(db_path, "admin", "SELECT 1") == "db_role_unconfigured"


def test_authorizer_follows_the_policy_it_was_given(db_path):
    table = readable_table("sales")
    column = sorted(POLICY.allowed_columns("sales", table))[0]
    narrowed = RolePolicy(
        version="test",
        schema=POLICY.schema,
        tables=POLICY.tables,
        roles={
            **POLICY.roles,
            "sales": {**POLICY.roles["sales"], table: frozenset()},
        },
        foreign_keys=POLICY.foreign_keys,
        functions=frozenset(),
        cast_types=POLICY.cast_types,
        limits=POLICY.limits,
    )

    with pytest.raises(ExecutorError) as raised:
        execute(db_path, "sales", f'SELECT "{column}" FROM "{table}"', policy=narrowed)
    assert raised.value.category == "db_permission_denied"
    with pytest.raises(ExecutorError) as raised:
        execute(db_path, "finance", f'SELECT COUNT(*) FROM "{table}"', policy=narrowed)
    assert raised.value.category == "db_permission_denied"


@pytest.mark.parametrize("role", ROLES)
def test_gate_off_still_blocks_forbidden_reads_at_the_database(db_path, role):
    table, column = forbidden_columns(role)[0]
    audit = InMemoryAuditSink()
    gate = PolicySQLGate(SecurityContext(role=role), POLICY, mode=GateMode.OFF)
    tool = SecureSqlTool(gate, SQLiteExecutor(db_path, POLICY), audit=audit)

    with pytest.raises(ToolError) as raised:
        asyncio.run(tool.call({"sql": f'SELECT "{column}" FROM "{table}"'}, timeout_seconds=3))

    assert raised.value.category == "db_permission_denied"
    assert not raised.value.retryable
    assert audit.records[-1].error_category == "db_permission_denied"


# SQLite does not call the authorizer for the columns a USING / NATURAL join compares, nor (with
# COUNT(*)) for the table itself: without the keyword check each query below returns 1 for a correct
# guess and 0 otherwise, for any role, even on a table outside the policy.
@pytest.mark.parametrize("role", ROLES)
@pytest.mark.parametrize(
    "sql",
    [
        "SELECT COUNT(*) FROM secret_table JOIN (SELECT 'CANARY-SECRET-0001' AS secret) "
        "USING (secret)",
        "SELECT COUNT(*) FROM secret_table NATURAL JOIN (SELECT 'CANARY-SECRET-0001' AS secret)",
        "SELECT x.secret FROM secret_table JOIN (SELECT 'CANARY-SECRET-0001' AS secret) x "
        "USING (secret)",
        "SELECT COUNT(*) FROM secret_table LEFT JOIN (SELECT 'CANARY-SECRET-0001' AS secret) x "
        "using(secret)",
        "SELECT COUNT(*) FROM secret_table JOIN (SELECT 'K' AS secret) x/**/UsInG\t(secret)",
        "SELECT COUNT(*) FROM secret_table JOIN (SELECT 'K' AS secret) x -- note\nUSING (secret)",
        # SQLite block comments do not nest: USING sits outside both comments.
        "SELECT COUNT(*) FROM secret_table JOIN (SELECT 'K' AS secret) x "
        "/* /* */ USING (secret) /* */",
        "SELECT COUNT(*), 'a''' FROM secret_table JOIN (SELECT 'K' AS secret) x USING (secret)",
    ],
)
def test_using_and_natural_joins_are_denied_because_the_authorizer_cannot_see_them(
    db_path, role, sql
):
    assert denied_category(db_path, role, sql) == "db_permission_denied"


@pytest.mark.parametrize("role", ROLES)
def test_using_join_cannot_probe_a_forbidden_column(db_path, role):
    table, column = forbidden_columns(role)[0]
    canary = next(
        (c.value for c in POLICY.canaries if (c.table, c.column) == (table, column)),
        f"{table}.{column}.1",
    )
    sql = (
        f'SELECT COUNT(*) FROM "{table}" JOIN (SELECT \'{canary}\' AS "{column}") x '
        f'USING ("{column}")'
    )

    assert denied_category(db_path, role, sql) == "db_permission_denied"


@pytest.mark.parametrize("role", ROLES)
def test_gate_off_still_blocks_a_using_join_probe(db_path, role):
    audit = InMemoryAuditSink()
    gate = PolicySQLGate(SecurityContext(role=role), POLICY, mode=GateMode.OFF)
    tool = SecureSqlTool(gate, SQLiteExecutor(db_path, POLICY), audit=audit)
    sql = (
        "SELECT COUNT(*) FROM secret_table JOIN (SELECT 'CANARY-SECRET-0001' AS secret) "
        "USING (secret)"
    )

    with pytest.raises(ToolError) as raised:
        asyncio.run(tool.call({"sql": sql}, timeout_seconds=3))

    assert raised.value.category == "db_permission_denied"
    assert not raised.value.retryable
    assert audit.records[-1].error_category == "db_permission_denied"


@pytest.mark.parametrize(
    "sql",
    [
        "SELECT 'using natural' AS note",
        "SELECT 'it''s using' AS note",
        'SELECT "using", "a""natural" FROM t',
        "SELECT `using`, [natural] FROM t",
        "SELECT 1 -- using\n",
        "SELECT 1 /* natural join ... using (x) */",
        "SELECT using_count, natural_key, x_using FROM t",
    ],
)
def test_keywords_inside_literals_identifiers_and_comments_are_not_flagged(sql):
    assert not has_unchecked_join(sql)


def test_allowed_query_mentioning_using_in_a_literal_still_runs(db_path):
    table = readable_table("sales")
    column = sorted(POLICY.allowed_columns("sales", table))[0]
    sql = f'SELECT COUNT(*) FROM "{table}" WHERE "{column}" <> \'using natural join\''

    assert execute(db_path, "sales", sql).rows == ((2,),)
