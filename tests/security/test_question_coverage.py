"""E4: the gate checks that the SQL still answers the question (section 15.6 of the workplan).

A forbidden table the question names but the SQL replaced is refused; a forbidden column the
question names but the SQL dropped is withheld with a notice, like a column the gate removed.
"""

import asyncio
import json
import unicodedata
from pathlib import Path

import pytest

from sqlguard.agent.controller import AgentController, RunScope
from sqlguard.agent.models import AgentRequest, RunStatus
from sqlguard.agent.planning import Plan
from sqlguard.agent.runtime import build_query_runtime_factory
from sqlguard.mcp.tools import InProcessToolRegistry
from sqlguard.memory.store import InMemoryMemory
from sqlguard.observability.events import InMemoryEventSink
from sqlguard.security.gate import DecisionKind, PolicySQLGate, ReadOnlySQLGate, SecurityContext
from sqlguard.security.policy import PolicyError, RolePolicy, load_policy
from sqlguard.security.question_coverage import check_question_coverage, named_resources

POLICY = load_policy("business_financial_v1")
SUITE = Path(__file__).resolve().parents[2] / "evaluation" / "datasets" / "financial"

LOANS_QUESTION = "Có bao nhiêu khoản vay được phê duyệt năm 1997?"
TRANS_INSTEAD = (
    "SELECT COUNT(*) FROM trans t JOIN account a ON t.account_id = a.account_id "
    "WHERE a.frequency = 'POPLATEK MESICNE'"
)
M01_QUESTION = "Cho biết họ tên, địa chỉ và số định danh của khách hàng mã 2."


def gate(role, question=None):
    return PolicySQLGate(SecurityContext(role=role, question=question), POLICY)


def test_terms_match_whole_words_case_and_unicode_form():
    decomposed = unicodedata.normalize("NFD", "Liệt kê THẺ và Địa Chỉ")

    assert named_resources(decomposed, POLICY) == {"card", "client.address"}
    assert named_resources("Có thể đếm số cards không?", POLICY) == frozenset()
    assert named_resources("cho biết card_id", POLICY) == {"card"}


def test_substituted_forbidden_table_is_refused_and_terminal():
    without = gate("analyst").check(TRANS_INSTEAD)
    refused = gate("analyst", LOANS_QUESTION).check(TRANS_INSTEAD)

    assert without.allowed
    assert not refused.allowed and refused.violations == ("question_needs_forbidden_data",)
    assert refused.repairable is False
    assert "loan" not in refused.reason and "id_number" not in refused.reason


def test_substitution_is_terminal_even_next_to_a_repairable_finding():
    # The A03 run of 24/10: the model's SQL also had a repairable error, so the run burnt its
    # attempts repairing a query that could never answer a question about loans.
    sql = "SELECT * FROM trans"
    assert gate("analyst").check(sql).repairable is True

    decision = gate("analyst", LOANS_QUESTION).check(sql)

    assert "question_needs_forbidden_data" in decision.violations
    assert decision.repairable is False


def test_named_forbidden_table_read_by_the_sql_stays_table_not_allowed():
    decision = gate("analyst", LOANS_QUESTION).check("SELECT COUNT(*) FROM loan")
    assert decision.violations == ("table_not_allowed",)


def test_question_naming_a_column_of_a_forbidden_table_is_refused():
    decision = gate("analyst", "Số thẻ của khách hàng ở Praha?").check(
        "SELECT district_id, COUNT(DISTINCT client_id) FROM client GROUP BY district_id"
    )
    assert decision.violations == ("question_needs_forbidden_data",)


def test_dropped_forbidden_column_is_withheld_with_a_notice():
    sql = "SELECT full_name, address FROM client WHERE client_id = 2"
    without = gate("operator").check(sql)
    decision = gate("operator", M01_QUESTION).check(sql)

    assert decision.kind is DecisionKind.ALLOW_PARTIAL
    assert decision.removed_columns == ("client.id_number",)
    assert "question_columns_withheld" in decision.notices
    assert decision.normalized_sql == without.normalized_sql


def test_column_the_gate_already_removed_is_not_reported_twice():
    sql = "SELECT full_name, address, id_number FROM client WHERE client_id = 2"
    decision = gate("operator", M01_QUESTION).check(sql)

    assert decision.removed_columns == ("client.id_number",)
    assert "question_columns_withheld" not in decision.notices


@pytest.mark.parametrize(
    ("role", "question", "sql"),
    [
        ("credit_officer", LOANS_QUESTION, "SELECT COUNT(*) FROM loan WHERE date >= '1997-01-01'"),
        (
            "operator",
            "Cho biết ghi chú dịch vụ của tài khoản 3.",
            "SELECT account_id, service_note FROM account WHERE account_id = 3",
        ),
        ("operator", "Liệt kê họ tên và địa chỉ khách hàng 1.", "SELECT full_name FROM client"),
    ],
)
def test_resources_the_role_may_read_change_nothing(role, question, sql):
    without = gate(role).check(sql)
    decision = gate(role, question).check(sql)

    assert (decision.kind, decision.removed_columns) == (without.kind, without.removed_columns)


def test_manual_sql_without_a_question_is_unchanged():
    decision = gate("analyst").check(TRANS_INSTEAD)
    assert decision.allowed and "question_columns_withheld" not in decision.notices


def test_policy_without_terms_skips_the_check():
    data = json.loads(
        (
            Path(__file__).resolve().parents[2] / "src/sqlguard/security/policies/"
            "business_financial_v1.json"
        ).read_text(encoding="utf-8")
    )
    del data["question_terms"]
    policy = RolePolicy.from_dict(data)

    decision = PolicySQLGate(
        SecurityContext(role="analyst", question=LOANS_QUESTION), policy
    ).check(TRANS_INSTEAD)
    assert decision.allowed


@pytest.mark.parametrize(
    "terms", [{"payments": ["x"]}, {"client.phone": ["x"]}, {"loan": []}, {"loan": [" "]}]
)
def test_question_terms_are_validated(terms):
    data = {"policy_version": "t", "tables": {"loan": ["loan_id"], "client": ["client_id"]}}
    with pytest.raises(PolicyError):
        RolePolicy.from_dict({**data, "roles": {}, "question_terms": terms})


def test_coverage_reports_forbidden_resources_only():
    coverage = check_question_coverage(M01_QUESTION + " Và các khoản vay?", POLICY, "operator")
    assert coverage.forbidden_tables == ("loan",)
    assert coverage.withheld_columns == ("client.id_number",)


def _tasks(name):
    document = json.loads((SUITE / f"{name}-tasks.v0.1.json").read_text(encoding="utf-8"))
    return document["tasks"] if isinstance(document, dict) else document


_REFERENCE = json.loads((SUITE / "sqlite-reference.v0.1.json").read_text(encoding="utf-8"))


@pytest.mark.parametrize("task", _tasks("legitimate"), ids=lambda task: task["id"])
def test_reference_sql_of_legitimate_tasks_is_never_refused_or_narrowed(task):
    # Measurement before turning refusals on (Q4): 0 false refusals on Kiet's legitimate suite.
    sql = _REFERENCE["results"][task["id"]]["sqlite_sql"]
    without = gate(task["role"]).check(sql)
    decision = gate(task["role"], task["question"]).check(sql)

    assert (decision.kind, decision.violations, decision.removed_columns) == (
        without.kind,
        without.violations,
        without.removed_columns,
    )


class _FixedPlanner:
    def __init__(self, sql):
        self.sql = sql

    async def create_plan(self, question, context):
        return Plan(sql=self.sql, summary="fixed")


def run_agent(financial_db, role, question, sql):
    env = {"SQLGUARD_QUERY_SOURCE": "sqlite", "SQLGUARD_SQLITE_PATH": str(financial_db)}
    factory = build_query_runtime_factory(role, env, policy=POLICY)
    tools = {}

    def scope_factory(run_id):
        runtime = factory.for_run(run_id, question=question)
        tools["tool"] = runtime.tool
        return RunScope(runtime.gate, InProcessToolRegistry([runtime.tool]))

    controller = AgentController(
        planner=_FixedPlanner(sql),
        tools=InProcessToolRegistry([]),
        security_gate=ReadOnlySQLGate(),
        memory=InMemoryMemory(),
        events=InMemoryEventSink(),
        run_scope_factory=scope_factory,
    )
    state = asyncio.run(controller.run(AgentRequest(question))).state
    return state, tools["tool"].last_decision


def test_agent_run_with_a_substituted_table_ends_refused(financial_db):
    state, _ = run_agent(financial_db, "analyst", LOANS_QUESTION, TRANS_INSTEAD)
    assert state.status is RunStatus.REFUSED


def test_agent_run_with_a_dropped_column_returns_a_partial_envelope(financial_db):
    sql = "SELECT full_name, address FROM client WHERE client_id = 2"
    state, tool_decision = run_agent(financial_db, "operator", M01_QUESTION, sql)

    assert state.status is RunStatus.SUCCEEDED
    assert "'removed_columns': ['client.id_number']" in state.final_answer
    assert tool_decision.removed_columns == ("client.id_number",)
