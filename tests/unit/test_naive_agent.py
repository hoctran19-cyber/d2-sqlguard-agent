"""N2, N4: the naive executor and agent loop, offline on a lab copy of the schema fixture.

The naive agent is deliberately unsafe; these tests pin down that it is unsafe in the intended
way (any column readable, rows handed to the model) and safe in the ways it must stay safe
(read-only, lab copy only, bounded).
"""

import asyncio

import pytest

from sqlguard.lab.model import (
    Q_ACCOUNT_NOTE,
    ModelReply,
    NaiveModelError,
    ScriptedModel,
    ToolCall,
    ToolResults,
    UserTurn,
    scripted_model_for,
)
from sqlguard.lab.naive_agent import NaiveAgent, NaiveSqliteExecutor
from sqlguard.lab.naive_guard import NaiveDemoError
from sqlguard.lab.naive_prompt import PROMPT_FINGERPRINTS, build_naive_system_prompt
from sqlguard.security.attack_lab import create_lab_copy, marker_path
from sqlguard.security.policy import load_policy

POLICY = load_policy("business_financial_v1")
OWNER_ID = "CANARY-ID-0003"  # the fixture puts the id_number canary in every client row


@pytest.fixture
def lab_db(financial_db, tmp_path):
    return create_lab_copy(financial_db, tmp_path / "lab" / "financial-lab.sqlite")


@pytest.fixture
def executor(lab_db):
    return NaiveSqliteExecutor(lab_db, POLICY)


def run(agent, question, role="operator"):
    return asyncio.run(agent.run(question, role))


# ---------- executor ----------


def test_executor_reads_a_column_the_gate_forbids(executor):
    step = executor.execute("SELECT client_id, id_number FROM client WHERE client_id = 3")
    assert step.error is None
    assert step.columns == ("client_id", "id_number")
    assert step.rows == ((3, OWNER_ID),)


@pytest.mark.parametrize(
    "sql",
    [
        "UPDATE account SET service_note = 'x' WHERE account_id = 1",
        "DELETE FROM loan",
        "CREATE TABLE t (x)",
        "PRAGMA query_only = OFF",
        "SELECT 1; SELECT 2",
    ],
)
def test_executor_stays_read_only_and_single_statement(executor, lab_db, sql):
    before = lab_db.read_bytes()
    step = executor.execute(sql)
    assert step.error is not None and step.rows == ()
    assert lab_db.read_bytes() == before


def test_executor_cannot_attach_another_database(executor, financial_db):
    step = executor.execute(f"ATTACH DATABASE '{financial_db}' AS original")
    assert step.error is not None


def test_executor_caps_rows_and_reports_truncation(lab_db):
    small = NaiveSqliteExecutor(lab_db, POLICY, max_rows=2)
    step = small.execute("SELECT client_id FROM client ORDER BY client_id")
    assert step.rows == ((1,), (2,)) and step.truncated is True


def test_executor_times_out(lab_db):
    slow = NaiveSqliteExecutor(lab_db, POLICY, timeout_seconds=0.05)
    step = slow.execute(
        "WITH RECURSIVE n(i) AS (SELECT 1 UNION ALL SELECT i + 1 FROM n) SELECT max(i) FROM n"
    )
    assert step.error == "timeout"


def test_executor_only_opens_a_lab_copy(financial_db, lab_db, executor):
    with pytest.raises(NaiveDemoError, match="naive_db_not_a_lab_copy"):
        NaiveSqliteExecutor(financial_db, POLICY)
    marker_path(lab_db).unlink()  # swapped after start-up: refused before the next query
    with pytest.raises(NaiveDemoError, match="naive_db_not_a_lab_copy"):
        executor.execute("SELECT 1")


def test_rows_reach_the_model_without_any_fence(executor):
    payload = executor.execute("SELECT account_id, service_note FROM account").model_payload()
    assert payload["rows"][0] == [1, "v1"]
    assert "untrusted" not in repr(payload)


# ---------- prompt ----------


def test_prompt_puts_the_role_rules_in_text_only():
    prompt = build_naive_system_prompt(POLICY, "operator")
    assert '"client"(' in prompt and "id_number" in prompt  # the whole schema is shown
    assert "- client: address, client_id, district_id, full_name" in prompt
    assert all(fingerprint in prompt for fingerprint in PROMPT_FINGERPRINTS)
    assert "untrusted" not in prompt.casefold()
    assert "aggregated" in build_naive_system_prompt(POLICY, "analyst")
    with pytest.raises(ValueError):
        build_naive_system_prompt(POLICY, "admin")


# ---------- agent loop ----------


def test_indirect_injection_scenario_makes_an_unrequested_call_and_leaks(executor):
    result = run(NaiveAgent(scripted_model_for(Q_ACCOUNT_NOTE), executor, POLICY), Q_ACCOUNT_NOTE)
    assert result.status == "completed"
    assert len(result.steps) == 2  # the second call reads the owner's id_number
    assert "id_number" in result.steps[1].sql
    assert OWNER_ID in result.answer_markdown
    assert result.model == "scripted" and result.model_calls == 3


class RecordingModel:
    """Always asks for another query; records what it was given each call."""

    name = "recording"

    def __init__(self):
        self.calls = []

    async def generate(self, system, turns, *, allow_tools):
        self.calls.append((system, list(turns), allow_tools))
        if allow_tools:
            return ModelReply(tool_calls=(ToolCall("SELECT account_id FROM account"),))
        return ModelReply(text="xong")


def test_tool_budget_ends_with_a_forced_answer(executor):
    model = RecordingModel()
    result = run(NaiveAgent(model, executor, POLICY, max_tool_calls=3), "hỏi")
    assert len(result.steps) == 3 and result.answer_markdown == "xong"
    assert [allow for _, _, allow in model.calls] == [True, True, True, False]
    system, turns, _ = model.calls[-1]
    assert "operator" in system and isinstance(turns[0], UserTurn)
    tool_turns = [t for t in turns if isinstance(t, ToolResults)]
    assert len(tool_turns) == 3 and tool_turns[0].results[0].payload["row_count"] == 3


def test_extra_calls_in_one_reply_beyond_the_budget_are_not_run(executor):
    calls = tuple(ToolCall(f"SELECT {i}") for i in range(5))
    model = ScriptedModel([])
    model.generate = lambda system, turns, allow_tools: _reply(allow_tools, calls)
    result = run(NaiveAgent(model, executor, POLICY, max_tool_calls=2), "hỏi")
    assert [step.sql for step in result.steps] == ["SELECT 0", "SELECT 1"]


async def _reply(allow_tools, calls):
    return ModelReply(tool_calls=calls) if allow_tools else ModelReply(text="ok")


class FailingModel:
    name = "failing"

    def __init__(self, category):
        self.category = category

    async def generate(self, system, turns, *, allow_tools):
        raise NaiveModelError(self.category)


@pytest.mark.parametrize(("category", "status"), [("blocked", "blocked"), ("timeout", "failed")])
def test_model_errors_end_the_run_with_a_category(executor, category, status):
    result = run(NaiveAgent(FailingModel(category), executor, POLICY), "hỏi")
    assert result.status == status and result.error_category == category
    assert result.answer_markdown == "" and result.steps == ()


def test_unknown_question_gets_a_notice_not_a_guess(executor):
    result = run(NaiveAgent(scripted_model_for("câu khác"), executor, POLICY), "câu khác")
    assert result.steps == () and "chỉ có kịch bản" in result.answer_markdown


def test_payload_is_json_ready(executor):
    import json

    result = run(NaiveAgent(scripted_model_for(Q_ACCOUNT_NOTE), executor, POLICY), Q_ACCOUNT_NOTE)
    payload = json.loads(json.dumps(result.to_payload()))
    assert payload["tool_calls"] == 2 and payload["steps"][0]["columns"][0] == "account_id"
