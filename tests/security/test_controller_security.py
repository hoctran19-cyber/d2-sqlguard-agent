"""The policy gate and secure tool plugged into the existing AgentController unchanged."""

import asyncio

from tests.security.fakes import SQLiteExecutor

from sqlguard.agent.controller import AgentController
from sqlguard.agent.models import AgentRequest, ExecutionBudget, RunStatus
from sqlguard.agent.planning import Plan
from sqlguard.mcp.tools import InProcessToolRegistry
from sqlguard.memory.store import InMemoryMemory
from sqlguard.observability.events import InMemoryEventSink
from sqlguard.security.audit import InMemoryAuditSink
from sqlguard.security.gate import PolicySQLGate, ReadOnlySQLGate, SecurityContext
from sqlguard.security.policy import load_default_policy
from sqlguard.security.service import SecureSqlTool, find_leaks

POLICY = load_default_policy()


class FixedPlanner:
    def __init__(self, sql):
        self.sql = sql

    async def create_plan(self, question, context):
        return Plan(sql=self.sql, summary="fixed")


def run(sql, *, role="sales", controller_gate=None):
    context = SecurityContext(role=role, user_id=f"{role}-demo", run_id="run-1")
    audit = InMemoryAuditSink()
    executor = SQLiteExecutor()
    tool = SecureSqlTool(PolicySQLGate(context, POLICY), executor, audit=audit)
    gate = controller_gate or PolicySQLGate(context, POLICY, audit=audit)
    events = InMemoryEventSink()
    controller = AgentController(
        planner=FixedPlanner(sql),
        tools=InProcessToolRegistry([tool]),
        security_gate=gate,
        memory=InMemoryMemory(),
        events=events,
        budget=ExecutionBudget(max_retries=2),
    )
    result = asyncio.run(controller.run(AgentRequest("question")))
    return result, executor, audit, events


def test_allowed_query_reaches_database_only_as_normalized_sql():
    result, executor, audit, _ = run("select full_name from customers where city = 'HCM'")

    assert result.state.status is RunStatus.SUCCEEDED
    assert executor.executed == ["SELECT full_name FROM customers WHERE city = 'HCM' LIMIT 100"]
    assert [(r.phase, r.outcome) for r in audit.records] == [
        ("gate", "allowed"),
        ("execute", "executed"),
    ]
    assert audit.records[0].input_hash == audit.records[1].input_hash


def test_partial_answer_succeeds_without_leaking():
    result, _, audit, _ = run("SELECT full_name, identity_number FROM customers")

    assert result.state.status is RunStatus.SUCCEEDED
    assert "customers.identity_number" in result.state.final_answer
    assert not find_leaks(result.state.final_answer, POLICY, "sales")
    assert audit.records[0].decision_kind == "allow_partial"


def test_policy_denial_refuses_before_tool_and_is_audited():
    result, executor, audit, events = run("SELECT bank_reference FROM payments")

    assert result.state.status is RunStatus.REFUSED
    assert executor.executed == []
    assert [(r.phase, r.outcome) for r in audit.records] == [("gate", "denied")]
    assert all(not hasattr(event, "sql") for event in events.events)


def test_tool_boundary_still_blocks_when_controller_gate_is_weaker():
    # Defense in depth: even with the legacy structural gate in the controller, the execute
    # boundary applies the role policy and the forbidden column never reaches the database.
    result, executor, audit, _ = run(
        "SELECT identity_number FROM customers", controller_gate=ReadOnlySQLGate()
    )

    assert result.state.status is RunStatus.FAILED
    assert result.state.failure_reason == "security_rejection"
    assert result.state.retry_count == 0
    assert executor.executed == []
    assert audit.records[-1].violations == ("column_forbidden",)


def test_operations_role_cannot_reach_payments():
    result, executor, _, _ = run("SELECT amount_vnd FROM payments", role="operations")

    assert result.state.status is RunStatus.REFUSED
    assert executor.executed == []
