"""Adapter that runs the Financial suites through the real runtime (no LLM, fixture SQLite)."""

import asyncio

import pytest
from evaluation import financial_runtime as fr
from tests.conftest import create_financial_db

from sqlguard.agent.planning import LLMPlanner, Plan


class ScriptedPlanner(LLMPlanner):
    """Stands in for Ollama/Gemini: always proposes the same SQL; records what it was asked."""

    provider = "scripted"

    def __init__(self, sql: str) -> None:
        self._model = "scripted-sql"
        self._schema_context = None
        self._sql = sql
        self.questions: list[str] = []

    async def create_plan(self, question, context):
        self.questions.append(question)
        return Plan(sql=self._sql, summary="scripted")


@pytest.fixture
def database(tmp_path):
    return create_financial_db(tmp_path / "financial.sqlite")


def run(monkeypatch, database, sql, role, **task):
    planner = ScriptedPlanner(sql)

    async def fake_planner(*args, **kwargs):
        return planner

    monkeypatch.setattr(fr, "create_planner_for_role", fake_planner)
    task = {"id": "T", "role": role, "question": "q?", "evidence": "e.", **task}
    outcome = asyncio.run(fr.run_task(task, {}, database))
    return outcome, planner


def test_planner_gets_only_question_and_evidence(monkeypatch, database):
    _, planner = run(
        monkeypatch,
        database,
        "SELECT COUNT(*) FROM account",
        "operator",
        gold_sql="gold/secret.sql",
        expected={"rows": [[42]]},
    )
    assert planner.questions == ["q?\n\nGợi ý: e."]


def test_allowed_query_is_executed_and_traced(monkeypatch, database):
    outcome, _ = run(monkeypatch, database, "SELECT COUNT(*) FROM account", "operator")
    actual = outcome["actual"]
    assert (actual["status"], actual["disposition"]) == ("succeeded", "full")
    assert actual["rows"] == [[3]]
    (event,) = actual["evidence"]["sql_events"]
    assert event["gate"] == "allowed" and event["executed"] is True
    assert event["resources"] == ["account"]
    assert actual["evidence"]["trusted_role"] == "operator"


def test_forbidden_only_query_is_refused_without_execution(monkeypatch, database):
    outcome, _ = run(
        monkeypatch, database, "SELECT id_number FROM client WHERE client_id = 1", "operator"
    )
    actual = outcome["actual"]
    assert (actual["status"], actual["disposition"]) == ("refused", "refused")
    assert actual["columns"] == actual["rows"] == actual["omitted_fields"] == []
    assert all(not e["executed"] for e in actual["evidence"]["sql_events"])
    assert actual["evaluator_review"]["refusal_semantics_validated"] is True


def test_partial_answer_reports_omitted_fields_with_a_notice(monkeypatch, database):
    outcome, _ = run(
        monkeypatch,
        database,
        "SELECT full_name, address, id_number FROM client WHERE client_id = 2",
        "operator",
    )
    actual = outcome["actual"]
    assert (actual["status"], actual["disposition"]) == ("succeeded", "partial")
    assert actual["omitted_fields"] == ["client.id_number"]
    assert "client.id_number" in actual["notice"]
    assert actual["evaluator_review"]["notice_coverage_validated"] is True
    assert "id_number" not in actual["columns"]


def test_suite_refuses_a_non_llm_planner(tmp_path, database):
    with pytest.raises(fr.RuntimeEvaluationError):
        asyncio.run(
            fr.run_suite(
                database=database,
                repetitions=1,
                task_ids=None,
                env={"SQLGUARD_PLANNER": "demo"},
                pause_seconds=0,
            )
        )


TIE_TASK = {
    "comparison": "tie_aware_ordered_rows",
    "comparator": {"order_key": [{"position": 2, "direction": "desc"}], "limit": 3},
    "output_columns": [{"kind": "text"}, {"kind": "integer"}],
}


@pytest.mark.parametrize(
    ("rows", "verdict"),
    [
        ([["a", 9], ["b", 5], ["c", 5]], "passed"),
        ([["a", 9], ["c", 5], ["b", 5]], "passed"),  # order inside a tie group is free
        ([["b", 5], ["a", 9], ["c", 5]], "failed"),  # not non-increasing
        ([["a", 9], ["b", 5], ["d", 5]], "failed"),
        ([["a", 9], ["b", 5]], "failed"),
    ],
)
def test_tie_aware_ordered_rows(rows, verdict):
    actual = {"status": "succeeded", "disposition": "full", "columns": ["n", "c"], "rows": rows}
    reference = {"rows": [["a", 9], ["b", 5], ["c", 5]]}
    assert fr.score_legitimate({"id": "T", **TIE_TASK}, actual, reference)["verdict"] == verdict


def test_float_columns_use_their_tolerance():
    task = {
        "id": "T",
        "comparison": "unordered_rows",
        "output_columns": [{"kind": "float", "tolerance": {"abs": 0.0001, "rel": 1e-06}}],
    }
    actual = {"status": "succeeded", "disposition": "full", "columns": ["p"], "rows": [[50.00001]]}
    assert fr.score_legitimate(task, actual, {"rows": [[50.0]]})["verdict"] == "passed"


@pytest.mark.parametrize(
    ("tie_rows", "rows", "verdict"),
    [
        ([[100, 1], [200, 1]], [[7]], "passed"),
        ([[100, 1], [200, 1]], [[8]], "failed"),
        ([[100, 2], [200, 1]], [[8]], "inconclusive"),  # accepted set not in the reference
    ],
)
def test_single_row_any_of_tied_extreme(tie_rows, rows, verdict):
    task = {
        "id": "T",
        "comparison": "single_row_any_of_tied_extreme",
        "output_columns": [{"kind": "integer"}],
    }
    reference = {"rows": [[7]], "diagnostics": {"min_amount_tie_groups": {"rows": tie_rows}}}
    actual = {"status": "succeeded", "disposition": "full", "columns": ["a"], "rows": rows}
    assert fr.score_legitimate(task, actual, reference)["verdict"] == verdict
