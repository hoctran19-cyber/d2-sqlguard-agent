"""Consistency checks for the 20 authorization tasks handed to the evaluation harness."""

import asyncio
import json
from pathlib import Path

import pytest
from tests.security.fakes import SQLiteExecutor

from sqlguard.security.gate import PolicySQLGate, SecurityContext
from sqlguard.security.policy import load_default_policy

ROOT = Path(__file__).resolve().parents[2]
DATASET = json.loads(
    (ROOT / "evaluation/datasets/security/authorization_tasks_v1.json").read_text(encoding="utf-8")
)
POLICY = load_default_policy()


def rows(sql):
    executor = SQLiteExecutor()
    result = asyncio.run(executor.execute(sql, role="", timeout_seconds=3, max_rows=100))
    return result.rows


def test_task_counts_and_ids():
    tasks = DATASET["tasks"]
    assert sum(t["category"] == "pure_auth" for t in tasks) == 10
    assert sum(t["category"] == "mixed" for t in tasks) == 10
    assert len({t["task_id"] for t in tasks}) == 20
    d2 = sorted(t["task_id"] for t in tasks if t["checkpoint"] == "D2")
    assert d2 == ["D2-A01", "D2-A02", "D2-M01", "D2-M02"]


@pytest.mark.parametrize("task", DATASET["tasks"], ids=lambda task: task["task_id"])
def test_task_matches_gate_and_reference_data(task):
    gate = PolicySQLGate(SecurityContext(task["role"]), POLICY)
    naive = gate.check(task["naive_sql"])
    assert str(naive.kind) == task["expected_gate_naive"]
    assert (naive.violations[:1] or (None,))[0] == task["expected_violation_naive"]

    if task["category"] == "pure_auth":
        assert task["expected_behavior"] == "refuse" and task["gold_sql"] is None
        assert not naive.allowed
        return

    assert task["expected_behavior"] == "partial" and task["gold_removed_columns"]
    gold = gate.check(task["gold_sql"])
    assert str(gold.kind) == "allow"
    gold_rows = rows(gold.normalized_sql)
    assert gold_rows, "gold SQL should return rows on the reference seed"
    if naive.allowed:
        # Automatic narrowing must keep exactly the gold row set (no silent filter change).
        assert list(naive.removed_columns) == task["gold_removed_columns"]
        assert rows(naive.normalized_sql) == gold_rows
    else:
        assert naive.repairable, "mixed tasks must stay answerable after a repair"
