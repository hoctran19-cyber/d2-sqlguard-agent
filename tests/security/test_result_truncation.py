"""F6: a result cut by the gate's LIMIT must be flagged truncated (real SQLite, not a fake).

The gate asks the database for one row over ``max_rows``; SecureSqlTool returns ``max_rows`` rows
at most and sets ``truncated`` only when that extra row exists.
"""

import asyncio
import sqlite3

import pytest
from tests.conftest import create_financial_db

from sqlguard.security.gate import PolicySQLGate, SecurityContext
from sqlguard.security.policy import load_policy
from sqlguard.security.service import SecureSqlTool
from sqlguard.security.sqlite import SQLiteExecutor

POLICY = load_policy("business_financial_v1")
MAX_ROWS = POLICY.limits.max_rows


def district_db(tmp_path, rows):
    # create_financial_db writes districts 1..3; add more so the table holds ``rows`` rows.
    path = create_financial_db(tmp_path / "financial.sqlite")
    with sqlite3.connect(path) as connection:
        connection.executemany(
            "INSERT INTO district (district_id, A2, A3) VALUES (?, 'd', 'r')",
            [(index,) for index in range(4, rows + 1)],
        )
    return path


def run(path, sql, role="operator"):
    gate = PolicySQLGate(SecurityContext(role=role), POLICY)
    tool = SecureSqlTool(gate, SQLiteExecutor(path, POLICY))
    return asyncio.run(tool.call({"sql": sql}, timeout_seconds=3))


@pytest.mark.parametrize(
    "sql", ["SELECT district_id FROM district", "SELECT district_id FROM district LIMIT 5000"]
)
def test_result_cut_by_the_gate_limit_is_flagged(tmp_path, sql):
    envelope = run(district_db(tmp_path, MAX_ROWS + 50), sql)
    assert envelope["row_count"] == MAX_ROWS
    assert envelope["truncated"] is True
    assert envelope["executed_sql"].endswith(f"LIMIT {MAX_ROWS + 1}")


def test_result_of_exactly_max_rows_is_not_flagged(tmp_path):
    envelope = run(district_db(tmp_path, MAX_ROWS), "SELECT district_id FROM district")
    assert envelope["row_count"] == MAX_ROWS
    assert envelope["truncated"] is False


def test_limit_chosen_by_the_caller_is_kept_and_not_flagged(tmp_path):
    envelope = run(
        district_db(tmp_path, MAX_ROWS + 50), f"SELECT district_id FROM district LIMIT {MAX_ROWS}"
    )
    assert envelope["row_count"] == MAX_ROWS
    assert envelope["truncated"] is False
    assert envelope["executed_sql"].endswith(f"LIMIT {MAX_ROWS}")


def test_analyst_grouped_result_reports_the_cut(tmp_path):
    # The Gemini run of 24/10: 1130 groups shown as 100 with truncated False.
    envelope = run(
        district_db(tmp_path, MAX_ROWS + 50),
        "SELECT district_id, COUNT(*) FROM district GROUP BY district_id",
        role="analyst",
    )
    assert envelope["row_count"] == MAX_ROWS
    assert envelope["truncated"] is True
