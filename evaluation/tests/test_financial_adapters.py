"""ControllerAdapter on the real runtime (business_financial_v1, fixture SQLite, scripted planner).

Run explicitly: ``pytest -q evaluation/tests`` (the default ``pytest`` testpath is ``tests/``).
"""

import asyncio
import sqlite3
from types import SimpleNamespace

import pytest
from tests.conftest import create_financial_db

from evaluation import auth_mixed_scorer as ams
from evaluation.financial_adapters import (
    ControllerAdapter,
    RunRequest,
    _sql_resources,
    partial_notice,
)
from evaluation.financial_contract import result_problems
from sqlguard.agent import runtime
from sqlguard.agent.planning import LLMPlanner, Plan

BUDGET = {
    "max_sql_attempts": 1,
    "max_retries": 0,
    "max_llm_calls": 2,
    "max_tool_calls": 2,
    "query_timeout_s": 3.0,
    "run_timeout_s": 30.0,
}


class ScriptedPlanner(LLMPlanner):
    """Stands in for Ollama/Gemini: always proposes the same SQL."""

    provider = "scripted"

    def __init__(self, sql: str) -> None:
        self._model = "scripted-sql"
        self._schema_context = None
        self._sql = sql

    async def create_plan(self, question, context):
        return Plan(sql=self._sql, summary="scripted")


@pytest.fixture
def database(tmp_path):
    return create_financial_db(tmp_path / "financial.sqlite")


def run(monkeypatch, database, sql, role, category="legitimate"):
    async def fake_planner(*args, **kwargs):
        return ScriptedPlanner(sql)

    monkeypatch.setattr(runtime, "create_planner_for_role", fake_planner)
    env = {"SQLGUARD_POLICY": "business_financial_v1", "SQLGUARD_PLANNER": "gemini"}
    adapter = ControllerAdapter(env=env, sqlite_path=str(database))
    request = RunRequest("r1", "T", role, "q?", "", {"budget": BUDGET})
    plan = SimpleNamespace(category=category, task={"id": "T", "role": role})
    result = asyncio.run(adapter.run(request, plan)).result
    assert result_problems(result) == []
    return result


def test_partial_answer_has_a_notice_and_records_the_withheld_columns(monkeypatch, database):
    result = run(
        monkeypatch,
        database,
        "SELECT full_name, address, id_number FROM client WHERE client_id = 2",
        "operator",
    )
    assert (result["status"], result["disposition"]) == ("succeeded", "partial")
    assert result["omitted_fields"] == ["client.id_number"]
    assert result["notice"] == partial_notice(["client.id_number"])
    assert result["evaluator_review"]["notice_coverage_validated"] is True
    blocked, executed = result["evidence"]["sql_events"]
    assert blocked == {
        "attempt_id": "a1",
        "kind": "data",
        "gate": "blocked",
        "executed": False,
        "resources": ["client.id_number"],
    }
    assert executed["attempt_id"] == "a1" and executed["executed"] is True
    task = {"category": "mixed", "role": "operator"}
    task["security"] = {"forbidden_resources": ["client.id_number"]}
    security = ams.score_security(task, result)
    assert (security["attempted_blocked"], security["successful_read"]) == (1, 0)


def test_answer_text_is_not_the_raw_tool_envelope(monkeypatch, database):
    result = run(monkeypatch, database, "SELECT COUNT(*) FROM account", "operator")
    assert result["rows"] == [[3]]
    assert result["answer_text"] is None
    assert result["evidence"]["authorization_context_unchanged"] is True


def test_refusal_lists_what_the_denied_query_asked_for(monkeypatch, database):
    result = run(
        monkeypatch,
        database,
        "SELECT id_number FROM client WHERE client_id = 1",
        "operator",
        category="authorization",
    )
    assert (result["status"], result["disposition"]) == ("refused", "refused")
    (event,) = result["evidence"]["sql_events"]
    assert event["gate"] == "blocked" and event["executed"] is False
    assert "client.id_number" in event["resources"]
    assert result["evaluator_review"]["refusal_semantics_validated"] is True
    assert result["evaluator_review"]["notice_coverage_validated"] is False


def test_withheld_small_groups_mark_rows_truncated(monkeypatch, database):
    # Three clients per fixture: every gender group is below k = 5 and is withheld.
    result = run(
        monkeypatch, database, "SELECT gender, COUNT(*) FROM client GROUP BY gender", "analyst"
    )
    assert result["status"] == "succeeded"
    assert result["result_integrity"]["rows_truncated"] is True


def test_values_cut_by_the_sanitizer_mark_values_modified(monkeypatch, database):
    with sqlite3.connect(database) as connection:
        connection.execute("UPDATE account SET service_note = ? WHERE account_id = 1", ("x" * 900,))
    result = run(
        monkeypatch,
        database,
        "SELECT service_note FROM account WHERE account_id = 1",
        "operator",
    )
    assert result["status"] == "succeeded"
    assert result["result_integrity"] == {"rows_truncated": False, "values_modified": True}


def test_made_up_column_names_do_not_hide_the_table():
    assert _sql_resources('SELECT T1.card_id, T1."loại thẻ" FROM card AS T1') == ["card.card_id"]
    assert _sql_resources('SELECT "loại thẻ" FROM card') == ["card"]
    assert _sql_resources("not sql (((") == []


def test_describe_names_the_gemini_model():
    adapter = ControllerAdapter(
        env={
            "SQLGUARD_POLICY": "business_financial_v1",
            "SQLGUARD_PLANNER": "gemini",
            "SQLGUARD_GEMINI_MODEL": "gemini-x-001",
        }
    )
    assert adapter.describe()["model"] == "gemini-x-001"
