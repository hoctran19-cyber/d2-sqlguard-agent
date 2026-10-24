"""Business-role policy ``business_financial_v1`` (workplan §14): operator, analyst, credit_officer.

The policy must say exactly what the reviewed role matrix says (``web/role_reference.py``, the
same table as ``db/Roles & Problem statement (edited).md``) and match the financial schema
contract. The gate enforces it per column; the analyst is aggregate-only. The SQLite tests use a
database generated from the policy, so they never need the real ``financial.sqlite``.
"""

import asyncio
import sqlite3

import pytest

from sqlguard.security.gate import GateMode, PolicySQLGate, SecurityContext
from sqlguard.security.policy import DIMENSION, KEY, MEASURE, PolicyError, RolePolicy, load_policy
from sqlguard.security.schema_preflight import FINANCIAL_FOREIGN_KEYS, FINANCIAL_SCHEMA_CONTRACT
from sqlguard.security.service import ExecutorError, SecureSqlTool
from sqlguard.security.sqlite import SQLiteExecutor
from sqlguard.web import role_reference

POLICY = load_policy("business_financial_v1")
ROLES = ("operator", "analyst", "credit_officer")
READ_ROLES = ("operator", "credit_officer")
REFERENCE_KINDS = {
    role_reference.READ: "read",
    role_reference.AGG_KEY: KEY,
    role_reference.AGG_DIMENSION: DIMENSION,
    role_reference.AGG_MEASURE: MEASURE,
}
ALL_COLUMNS = sorted((t, c) for t, columns in POLICY.tables.items() for c in columns)


def check(role, sql, **kwargs):
    return PolicySQLGate(SecurityContext(role), POLICY, **kwargs).check(sql)


def quoted(table):
    return f'"{table}"'


# -- the policy says what the matrix says ------------------------------------------------------


def test_policy_matches_the_reviewed_role_matrix():
    assert set(POLICY.roles) == set(ROLES)
    for role in ROLES:
        expected = {
            (table.casefold(), column.casefold()): REFERENCE_KINDS[access]
            for table, columns in role_reference._ROLE_ALLOWLISTS[role].items()
            for column, access in columns.items()
        }
        actual = {
            (table, column): POLICY.column_kind(role, table, column) or "read"
            for table in POLICY.allowed_tables(role)
            for column in POLICY.allowed_columns(role, table)
        }
        assert actual == expected, role
    assert POLICY.is_aggregate_only("analyst")
    assert not any(POLICY.is_aggregate_only(role) for role in READ_ROLES)


def test_policy_matches_the_schema_contract():
    contract = {
        table: {column.casefold() for column in columns}
        for table, columns in FINANCIAL_SCHEMA_CONTRACT.items()
    }
    assert {table: set(columns) for table, columns in POLICY.tables.items()} == contract
    assert sum(map(len, POLICY.tables.values())) == 61
    assert POLICY.foreign_keys == {
        frozenset({(a, b), (c, d)}) for a, b, c, d in FINANCIAL_FOREIGN_KEYS
    }
    assert (POLICY.dialect, POLICY.schema) == ("sqlite", "main")


def test_no_role_reads_the_canary_columns():
    assert {(c.table, c.column) for c in POLICY.canaries} == {
        ("client", "id_number"),
        ("card", "placeholder"),
    }
    for role in ROLES:
        assert POLICY.canaries_for(role) == POLICY.canaries


def test_aggregate_grants_must_cover_every_table_of_the_role():
    data = {
        "policy_version": "t",
        "tables": {"a": ["x"], "b": ["y"]},
        "roles": {"r": {"a": {"x": KEY}, "b": ["y"]}},
    }
    with pytest.raises(PolicyError):
        RolePolicy.from_dict(data)
    data["roles"]["r"] = {"a": {"x": "secret"}}
    with pytest.raises(PolicyError):
        RolePolicy.from_dict(data)
    data["dialect"] = "mysql"
    data["roles"]["r"] = {"a": ["x"]}
    with pytest.raises(PolicyError):
        RolePolicy.from_dict(data)


# -- operator and credit_officer: plain column reads -------------------------------------------


@pytest.mark.parametrize("role", READ_ROLES)
@pytest.mark.parametrize(("table", "column"), ALL_COLUMNS)
def test_read_roles_follow_the_column_matrix(role, table, column):
    readable = POLICY.can_read(role, table, column)
    shown = check(role, f"SELECT {column} FROM {quoted(table)}")
    filtered = check(role, f"SELECT COUNT(*) FROM {quoted(table)} WHERE {column} IS NOT NULL")
    ordered = check(role, f"SELECT COUNT(*) FROM {quoted(table)} ORDER BY {column}")
    if readable:
        assert shown.allowed and filtered.allowed and ordered.allowed
    elif table not in POLICY.allowed_tables(role):
        for decision in (shown, filtered, ordered):
            assert decision.violations == ("table_not_allowed",)
    else:
        for decision in (shown, filtered, ordered):
            assert decision.violations == ("column_forbidden",)


def test_forbidden_display_columns_are_dropped_not_returned():
    decision = check("operator", "SELECT client_id, full_name, id_number FROM client")
    assert decision.removed_columns == ("client.id_number",)
    assert "id_number" not in decision.normalized_sql
    decision = check("credit_officer", 'SELECT order_id, amount, bank_to FROM "order"')
    assert decision.removed_columns == ("order.bank_to",)


def test_credit_officer_loan_follow_up_query():
    sql = (
        "SELECT l.loan_id, c.full_name, l.amount, l.duration, l.status FROM loan l "
        "JOIN account a ON l.account_id = a.account_id "
        "JOIN disp d ON d.account_id = a.account_id "
        "JOIN client c ON d.client_id = c.client_id "
        "WHERE l.status = 'D' AND d.type = 'OWNER'"
    )
    assert check("credit_officer", sql).allowed
    assert check("operator", sql).violations == ("table_not_allowed",)
    assert not check("analyst", sql).allowed


# -- analyst: aggregate-only -------------------------------------------------------------------

ANALYST_ALLOWED = [
    "SELECT gender, COUNT(*) FROM client GROUP BY gender",
    "SELECT COUNT(DISTINCT client_id) FROM client",
    "SELECT COUNT(account_id) FROM account",
    "SELECT d.a3, COUNT(DISTINCT t.account_id) AS accounts, SUM(t.amount) AS total FROM trans t "
    "JOIN account a ON t.account_id = a.account_id "
    "JOIN district d ON a.district_id = d.district_id GROUP BY d.a3 ORDER BY total DESC",
    "SELECT strftime('%Y-%m', date) AS month, COUNT(*) FROM account GROUP BY month",
    "SELECT SUBSTR(date, 1, 4) AS y, AVG(amount) FROM trans GROUP BY 1",
    "SELECT type, SUM(CASE WHEN operation = 'VYBER' THEN amount ELSE 0 END) FROM trans "
    "GROUP BY type",
    "SELECT district.a2, AVG(district.a11) FROM district GROUP BY a2",
    "SELECT frequency, COUNT(*) FROM account WHERE date >= '1997-01-01' GROUP BY frequency "
    "HAVING COUNT(DISTINCT account_id) > 10",
    "SELECT SUM(amount) FROM trans",
    # Regional statistics are district-level context, not personal data: they may filter (Kiet's
    # legitimate tasks D2-L04 and D2-L06 in their SQLite form).
    "SELECT COUNT(DISTINCT T1.client_id) FROM client AS T1 INNER JOIN district AS T2 "
    "ON T1.district_id = T2.district_id WHERE T1.gender = 'M' AND T2.a3 = 'north Bohemia' "
    "AND T2.a11 > 8000",
    "SELECT SUM(CASE WHEN T2.gender = 'F' THEN 1 ELSE 0 END) * 100.0 / "
    "COUNT(DISTINCT T2.client_id) FROM district AS T1 INNER JOIN client AS T2 "
    "ON T1.district_id = T2.district_id WHERE T1.a11 > 10000",
]

ANALYST_DENIED = [
    # Individual keys: output, grouping, filtering, ordering or a non-COUNT aggregate.
    ("SELECT account_id, SUM(amount) FROM trans GROUP BY account_id", "aggregate_key_exposed"),
    ("SELECT COUNT(*) FROM trans GROUP BY account_id", "aggregate_key_exposed"),
    ("SELECT SUM(amount) FROM trans WHERE account_id = 5", "aggregate_key_exposed"),
    ("SELECT SUM(amount) FROM trans WHERE trans_id IN (1, 2)", "aggregate_key_exposed"),
    ("SELECT COUNT(*) FROM client ORDER BY client_id", "aggregate_key_exposed"),
    ("SELECT MAX(trans_id) FROM trans", "aggregate_key_exposed"),
    ("SELECT MIN(client_id) FROM client", "aggregate_key_exposed"),
    ("SELECT SUM(amount * account_id) FROM trans", "aggregate_key_exposed"),
    ("SELECT COUNT(CASE WHEN account_id = 5 THEN 1 END) FROM trans", "aggregate_key_exposed"),
    (
        "SELECT gender, COUNT(*) FROM client GROUP BY gender HAVING MAX(client_id) > 0",
        "aggregate_key_exposed",
    ),
    # Measures outside an aggregate.
    ("SELECT COUNT(*) FROM trans WHERE amount > 1000", "aggregate_measure_exposed"),
    ("SELECT type, COUNT(*) FROM trans GROUP BY type, amount", "aggregate_measure_exposed"),
    # Regional statistics as filters do not open per-transaction amounts.
    (
        "SELECT COUNT(*) FROM trans t JOIN account a ON t.account_id = a.account_id "
        "JOIN district d ON a.district_id = d.district_id WHERE d.a11 > 8000 AND t.amount > 5",
        "aggregate_measure_exposed",
    ),
    # Row-level output.
    ("SELECT gender FROM client", "aggregate_required"),
    ("SELECT DISTINCT a2 FROM district", "aggregate_required"),
    ("SELECT a2, SUM(a4) FROM district", "aggregate_required"),
    ("SELECT gender, district_id, COUNT(*) FROM client GROUP BY gender", "aggregate_required"),
    ("SELECT 1", "aggregate_required"),
    # Forbidden columns and tables stay forbidden.
    ("SELECT COUNT(*) FROM client WHERE full_name LIKE 'A%'", "column_forbidden"),
    ("SELECT COUNT(*) FROM trans WHERE balance > 0", "column_forbidden"),
    ("SELECT COUNT(*) FROM loan", "table_not_allowed"),
    ('SELECT COUNT(*) FROM "order"', "table_not_allowed"),
    ("SELECT COUNT(*) FROM card", "table_not_allowed"),
    ("SELECT name FROM sqlite_master", "system_catalog"),
    # Shapes the gate does not support at all.
    ("SELECT COUNT(*) FROM (SELECT account_id FROM trans) t", "subquery_not_supported"),
    ("SELECT * FROM district", "star_not_allowed"),
]


@pytest.mark.parametrize("sql", ANALYST_ALLOWED)
def test_analyst_aggregate_queries_are_allowed(sql):
    decision = check("analyst", sql)
    assert decision.allowed, decision.violations


@pytest.mark.parametrize(("sql", "violation"), ANALYST_DENIED)
def test_analyst_row_level_queries_are_denied(sql, violation):
    decision = check("analyst", sql)
    assert not decision.allowed
    assert violation in decision.violations


def test_analyst_key_misuse_is_terminal_and_shape_errors_are_repairable():
    assert not check("analyst", "SELECT COUNT(*) FROM trans GROUP BY account_id").repairable
    assert check("analyst", "SELECT gender FROM client").repairable
    assert check("analyst", "SELECT COUNT(*) FROM trans WHERE amount > 0").repairable


def test_analyst_forbidden_display_column_is_dropped_before_the_aggregate_check():
    decision = check("analyst", "SELECT full_name, COUNT(*) FROM client GROUP BY district_id")
    assert decision.allowed and decision.removed_columns == ("client.full_name",)
    assert not check("analyst", "SELECT full_name FROM client").allowed


def test_analyst_aggregate_check_applies_only_in_column_level_mode():
    sql = "SELECT COUNT(*) FROM trans GROUP BY account_id"
    assert check("analyst", sql, mode=GateMode.OFF).allowed
    # Table-level baseline: the analyst has no fully readable table.
    assert check("analyst", sql, mode=GateMode.TABLE_LEVEL).violations == ("table_not_allowed",)


@pytest.mark.parametrize(("table", "column"), ALL_COLUMNS)
def test_analyst_follows_the_column_kinds(table, column):
    kind = POLICY.column_kind("analyst", table, column)
    t = quoted(table)
    as_dimension = check("analyst", f"SELECT {column}, COUNT(*) FROM {t} GROUP BY {column}")
    as_count = check("analyst", f"SELECT COUNT(DISTINCT {column}) FROM {t}")
    as_sum = check("analyst", f"SELECT SUM({column}) FROM {t}")
    if kind == DIMENSION:
        assert as_dimension.allowed and as_count.allowed and as_sum.allowed
    elif kind == KEY:
        assert as_dimension.violations == ("aggregate_key_exposed",)
        assert as_count.allowed
        assert as_sum.violations == ("aggregate_key_exposed",)
    elif kind == MEASURE:
        assert as_dimension.violations == ("aggregate_measure_exposed",)
        assert as_count.allowed and as_sum.allowed
    else:
        assert not (as_dimension.allowed or as_count.allowed or as_sum.allowed)


# -- SQLite dialect ----------------------------------------------------------------------------


def test_sql_is_normalized_in_the_sqlite_dialect():
    decision = check("analyst", "SELECT SUBSTR(date, 1, 7) AS m, COUNT(*) FROM trans GROUP BY m")
    assert "SUBSTRING(date, 1, 7)" in decision.normalized_sql
    assert check("operator", "SELECT client_id FROM main.client").allowed
    assert check("operator", "SELECT client_id FROM public.client").violations == (
        "schema_not_allowed",
    )
    for table in ("sqlite_master", "sqlite_schema", "sqlite_sequence", "sqlite_stat1"):
        assert check("operator", f"SELECT name FROM {table}").violations == ("system_catalog",)


# -- end to end on a generated SQLite database -------------------------------------------------


@pytest.fixture
def db_path(tmp_path):
    path = tmp_path / "business.sqlite"
    canaries = {(c.table, c.column): c.value for c in POLICY.canaries}
    with sqlite3.connect(path) as connection:
        for table, columns in sorted(POLICY.tables.items()):
            ordered = sorted(columns)
            connection.execute(f'CREATE TABLE "{table}" ({", ".join(ordered)})')
            for row in (1, 2, 3):
                numeric = {c for c in ordered if c.endswith("_id") or c == "amount"}
                values = [
                    canaries.get((table, c), row if c in numeric else f"v{row}") for c in ordered
                ]
                placeholders = ", ".join("?" for _ in ordered)
                connection.execute(f'INSERT INTO "{table}" VALUES ({placeholders})', values)
    connection.close()
    return path


def run_tool(path, role, sql, mode=GateMode.COLUMN_LEVEL):
    gate = PolicySQLGate(SecurityContext(role), POLICY, mode=mode)
    tool = SecureSqlTool(gate, SQLiteExecutor(path, POLICY))
    return asyncio.run(tool.call({"sql": sql}, timeout_seconds=3))


def test_each_role_runs_its_own_queries_on_sqlite(db_path):
    operator = run_tool(db_path, "operator", "SELECT client_id, full_name, id_number FROM client")
    assert operator["columns"] == ["client_id", "full_name"]
    assert "CANARY" not in str(operator["rows"])
    analyst = run_tool(
        db_path,
        "analyst",
        "SELECT gender, COUNT(DISTINCT client.client_id), SUM(t.amount) FROM client "
        "JOIN disp d ON d.client_id = client.client_id "
        "JOIN account a ON d.account_id = a.account_id "
        "JOIN trans t ON t.account_id = a.account_id GROUP BY gender",
    )
    # The query runs; every group here covers fewer than min_group_size clients (3 rows per
    # table), so all are withheld (see test_small_group_suppression.py).
    assert analyst["columns"] == ["gender", "COUNT(DISTINCT client.client_id)", "SUM(t.amount)"]
    assert analyst["rows"] == [] and analyst["small_groups_withheld"] is True
    credit = run_tool(db_path, "credit_officer", "SELECT loan_id, amount, status FROM loan")
    assert credit["row_count"] == 3


@pytest.mark.parametrize(
    ("role", "sql"),
    [
        ("analyst", "SELECT full_name FROM client"),
        ("analyst", "SELECT amount FROM loan"),
        ("operator", "SELECT id_number FROM client"),
        ("operator", "SELECT birth_date FROM client"),
        ("credit_officer", "SELECT address FROM client"),
        ("credit_officer", "SELECT placeholder FROM card"),
    ],
)
def test_the_database_refuses_forbidden_columns_without_the_gate(db_path, role, sql):
    with pytest.raises(Exception) as raised:
        run_tool(db_path, role, sql, mode=GateMode.OFF)
    assert getattr(raised.value, "category", None) == "db_permission_denied"


def test_the_database_layer_does_not_enforce_aggregate_only(db_path):
    # Documented limitation: the authorizer sees columns, not query shape, so with the gate off
    # the analyst can read keys row by row. Aggregate-only is enforced by the gate alone.
    result = run_tool(db_path, "analyst", "SELECT account_id FROM trans", mode=GateMode.OFF)
    assert result["row_count"] == 3


def test_executor_rejects_unknown_role(db_path):
    executor = SQLiteExecutor(db_path, POLICY)
    with pytest.raises(ExecutorError):
        asyncio.run(executor.execute("SELECT 1", role="teller", timeout_seconds=1, max_rows=1))
