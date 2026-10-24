"""F5: small-group suppression for aggregate-only roles (business_financial_v1, k = 5, provisional).

The gate appends COUNT(DISTINCT <cohort key>) for every table holding individuals; SecureSqlTool
drops groups below ``limits.min_group_size``, strips the counts and only says that something was
withheld. Queries may not use the reserved prefix, so the counts cannot be forged.
"""

import asyncio
import sqlite3

import pytest

from sqlguard.security.gate import GROUP_COUNT_PREFIX, PolicySQLGate, SecurityContext
from sqlguard.security.policy import load_policy
from sqlguard.security.service import SecureSqlTool, suppress_small_groups
from sqlguard.security.sqlite import SQLiteExecutor

POLICY = load_policy("business_financial_v1")
K = POLICY.limits.min_group_size


def check(role, sql):
    return PolicySQLGate(SecurityContext(role), POLICY).check(sql)


def test_policy_sets_a_provisional_threshold_and_cohort_keys():
    assert K == 5
    assert POLICY.cohort_keys == {
        "client": "client_id",
        "disp": "client_id",
        "account": "account_id",
        "trans": "account_id",
    }


def test_gate_adds_group_counts_for_the_analyst_only():
    sql = "SELECT d.a3, SUM(t.amount) FROM trans t JOIN account a ON t.account_id = a.account_id "
    sql += "JOIN district d ON a.district_id = d.district_id GROUP BY d.a3"
    analyst = check("analyst", sql)
    assert analyst.allowed and "group_counts_added" in analyst.notices
    assert f"COUNT(DISTINCT a.account_id) AS {GROUP_COUNT_PREFIX}0" in analyst.normalized_sql
    assert f"COUNT(DISTINCT t.account_id) AS {GROUP_COUNT_PREFIX}2" in analyst.normalized_sql
    # district holds no individuals: no count for it.
    assert analyst.normalized_sql.count(GROUP_COUNT_PREFIX) == 2
    assert check("analyst", "SELECT a3, AVG(a11) FROM district GROUP BY a3").notices == (
        "limit_added",
    )
    operator = check("operator", "SELECT client_id, full_name FROM client")
    assert GROUP_COUNT_PREFIX not in operator.normalized_sql


def test_positional_references_still_point_at_the_user_columns():
    decision = check("analyst", "SELECT gender, COUNT(*) FROM client GROUP BY 1 ORDER BY 2 DESC")
    assert decision.allowed
    assert decision.normalized_sql.index("GROUP BY 1") > decision.normalized_sql.index(
        GROUP_COUNT_PREFIX
    )


@pytest.mark.parametrize("role", ["analyst", "operator", "credit_officer"])
@pytest.mark.parametrize(
    "sql",
    [
        f"SELECT gender, COUNT(*) AS {GROUP_COUNT_PREFIX}0 FROM client GROUP BY gender",
        "SELECT COUNT(*) AS __SQLGUARD_GROUP_9 FROM account",
        'SELECT COUNT(*) FROM account AS "__sqlguard_x"',
    ],
)
def test_the_reserved_prefix_cannot_be_used_by_queries(role, sql):
    assert "unsupported_syntax" in check(role, sql).violations


def test_suppress_small_groups_drops_rows_and_strips_counts():
    columns = ("gender", "n", f"{GROUP_COUNT_PREFIX}0", f"{GROUP_COUNT_PREFIX}1")
    rows = [("F", 9, 9, 7), ("M", 4, 4, 9), ("X", 7, 7, None)]
    visible, kept, withheld = suppress_small_groups(columns, rows, 5)
    assert visible == ("gender", "n")
    assert kept == [("F", 9)]
    assert withheld is True
    assert suppress_small_groups(("a",), [(1,)], 5) == (("a",), [(1,)], False)


@pytest.fixture
def db_path(tmp_path):
    """Generated from the policy: 7 female and 2 male clients, one account per client, and one
    account with a single large transaction (the F5 pattern: a group of one individual)."""
    path = tmp_path / "suppression.sqlite"
    with sqlite3.connect(path) as connection:
        for table, columns in sorted(POLICY.tables.items()):
            connection.execute(f'CREATE TABLE "{table}" ({", ".join(sorted(columns))})')

        def insert(table, **values):
            names = ", ".join(values)
            marks = ", ".join("?" for _ in values)
            connection.execute(
                f'INSERT INTO "{table}" ({names}) VALUES ({marks})', tuple(values.values())
            )

        insert("district", district_id=1, a2="Benesov", a3="central Bohemia", a11=8000)
        for client_id in range(1, 10):
            gender = "F" if client_id <= 7 else "M"
            insert("client", client_id=client_id, gender=gender, district_id=1)
            insert("account", account_id=client_id, district_id=1, frequency="M", date="1997-01-01")
            insert(
                "disp", disp_id=client_id, client_id=client_id, account_id=client_id, type="OWNER"
            )
            insert(
                "trans",
                trans_id=client_id,
                account_id=client_id,
                date="1997-02-01",
                type="PRIJEM",
                operation="VKLAD",
                amount=100,
                k_symbol="SIPO",
            )
        insert(
            "trans",
            trans_id=99,
            account_id=9,
            date="1997-03-01",
            type="VYDAJ",
            operation="VYBER",
            amount=987654,
            k_symbol="UVER",
        )
    connection.close()
    return path


def run(path, role, sql):
    tool = SecureSqlTool(PolicySQLGate(SecurityContext(role), POLICY), SQLiteExecutor(path, POLICY))
    return asyncio.run(tool.call({"sql": sql}, timeout_seconds=3))


def test_groups_below_the_threshold_are_withheld_on_sqlite(db_path):
    result = run(db_path, "analyst", "SELECT gender, COUNT(*) FROM client GROUP BY gender")
    assert result["columns"] == ["gender", "COUNT(*)"]
    assert result["rows"] == [["F", 7]]
    assert result["small_groups_withheld"] is True
    assert GROUP_COUNT_PREFIX in result["executed_sql"]


def test_fine_grained_grouping_cannot_isolate_one_account(db_path):
    # Gemini's rewrite of "list the transactions" (F5): group so finely that a group is one account.
    sql = (
        "SELECT strftime('%Y-%m', date) AS month, type, operation, k_symbol, "
        "COUNT(DISTINCT account_id) AS accounts, SUM(amount) AS total "
        "FROM trans GROUP BY month, type, operation, k_symbol"
    )
    result = run(db_path, "analyst", sql)
    assert all(987654 not in row for row in result["rows"])
    assert result["rows"] == [["1997-02", "PRIJEM", "VKLAD", "SIPO", 9, 900]]
    assert result["small_groups_withheld"] is True


def test_a_filter_narrowing_to_few_individuals_is_withheld(db_path):
    result = run(db_path, "analyst", "SELECT SUM(amount) FROM trans WHERE k_symbol = 'UVER'")
    assert result["rows"] == [] and result["small_groups_withheld"] is True
    total = run(db_path, "analyst", "SELECT SUM(amount) FROM trans")
    assert total["rows"] == [[900 + 987654]] and total["small_groups_withheld"] is False


def test_read_roles_are_not_suppressed(db_path):
    result = run(db_path, "credit_officer", "SELECT client_id, full_name FROM client")
    assert result["row_count"] == 9 and result["small_groups_withheld"] is False
