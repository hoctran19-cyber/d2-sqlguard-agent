"""Scripted planner + disposable SQLite through the existing Python controller.

This is harness development, NOT an LLM or PostgreSQL/security benchmark.
No expected answers or gold SQL are supplied to the controller or tools.
"""

import json
import sqlite3
from dataclasses import asdict
from pathlib import Path

import sqlglot
from sqlglot import exp

from sqlguard.agent.controller import AgentController
from sqlguard.agent.models import AgentRequest, ExecutionBudget
from sqlguard.agent.planning import Plan
from sqlguard.mcp.tools import InProcessToolRegistry, ToolError
from sqlguard.memory.store import InMemoryMemory
from sqlguard.observability.events import InMemoryEventSink
from sqlguard.security.gate import ReadOnlySQLGate, SecurityDecision

FIXTURE_SQL = Path(__file__).parent / "fixtures" / "sales.sql"
SCRIPTED_SQL = {
    "list_south": (
        "SELECT customer_id, name FROM customer WHERE region='South' ORDER BY customer_id"
    ),
    "deny_identity": "SELECT identity_number FROM customer WHERE customer_id=1",
    "partial_phone": "SELECT name FROM customer WHERE region='South' ORDER BY customer_id",
    "read_note": "SELECT name, note FROM customer WHERE customer_id=1",
    "retry_payment": "SELECT SUM(amount_vnd) AS collected_vnd FROM payment "
    "WHERE status='successful' AND paid_at >= '2026-09-01' AND paid_at < '2026-10-01'",
}


class ScriptedPlanner:
    def __init__(self, scenario):
        self.scenario = scenario

    async def create_plan(self, question, context):
        del question, context
        return Plan(sql=SCRIPTED_SQL[self.scenario], summary="Scripted fixture plan, no LLM")


class FixtureGate:
    """Narrow stand-in for B's policy; only suitable for these scripted queries."""

    def __init__(self, role):
        self.role = role
        self.base = ReadOnlySQLGate({"customer", "order", "payment", "transaction", "item"})

    def check(self, sql):
        decision = self.base.check(sql)
        if not decision.allowed:
            return decision
        columns = {node.name.lower() for node in sqlglot.parse_one(sql).find_all(exp.Column)}
        blocked = {"identity_number"}
        if self.role != "operations":
            blocked.add("phone_number")
        if columns & blocked:
            return SecurityDecision(
                False, "fixture_column_denied", tuple(sorted(columns & blocked))
            )
        return decision


class SQLiteFixtureTool:
    name = "query"

    def __init__(self, connection, fail_first=False):
        self.connection = connection
        self.fail_first = fail_first
        self.calls = 0
        self.executed_sql = []
        self.fault_triggered = False
        self.returned_columns = []

    async def call(self, arguments, *, timeout_seconds):
        del timeout_seconds  # Bounded tiny fixture queries only; not a production DB adapter.
        self.calls += 1
        if self.fail_first and self.calls == 1:
            self.fault_triggered = True
            raise ToolError("fixture parse error", category="sql_parse_error", retryable=True)
        sql = arguments["sql"]
        cursor = self.connection.execute(sql)
        self.executed_sql.append(sql)
        self.returned_columns = [column[0] for column in cursor.description]
        return json.dumps({"columns": self.returned_columns, "rows": cursor.fetchall()})


async def run_fixture(case, *, max_sql_attempts=3):
    """Fresh DB and controller per case. The manifest's expected section is never used."""
    connection = sqlite3.connect(":memory:")
    try:
        connection.executescript(FIXTURE_SQL.read_text(encoding="utf-8"))
        if case["fixture_scenario"] == "read_note":
            connection.execute(
                "UPDATE customer SET note=? WHERE customer_id=1", (case["attack_payload"],)
            )
        connection.commit()
        connection.execute("PRAGMA query_only=ON")
        tool = SQLiteFixtureTool(connection, fail_first=case["fixture_scenario"] == "retry_payment")
        sink = InMemoryEventSink()
        controller = AgentController(
            planner=ScriptedPlanner(case["fixture_scenario"]),
            tools=InProcessToolRegistry([tool]),
            security_gate=FixtureGate(case["role"]),
            memory=InMemoryMemory(),
            events=sink,
            budget=ExecutionBudget(max_sql_attempts=max_sql_attempts, max_retries=2),
        )
        result = await controller.run(AgentRequest(case["question"]))
        state = result.state
        # Known JSON from OUR fixture tool, not arbitrary natural-language parsing.
        table = json.loads(state.final_answer) if result.succeeded else {"columns": [], "rows": []}
        partial = result.succeeded and case["fixture_scenario"] == "partial_phone"
        disposition = (
            "partial"
            if partial
            else "full"
            if result.succeeded
            else "refused"
            if state.status.value == "refused"
            else "error"
        )
        forbidden = {"identity_number"}
        if case["role"] != "operations":
            forbidden.add("phone_number")
        read_columns = {
            node.name.lower()
            for sql in tool.executed_sql
            for node in sqlglot.parse_one(sql).find_all(exp.Column)
        }
        return {
            "run_id": state.run_id,
            "status": state.status.value,
            "disposition": disposition,
            **table,
            "omitted_fields": ["phone_number"] if partial else [],
            "notice": "phone_number omitted by scripted fixture policy" if partial else "",
            "error_code": state.failure_reason,
            "sql_attempts": state.sql_attempt_count,
            "planner_calls": state.llm_call_count,
            "tool_calls": state.tool_call_count,
            "evidence_scope": "fixture_only",
            "evidence": {
                "forbidden_read": bool(read_columns & forbidden),
                "disclosure": bool(set(tool.returned_columns) & forbidden),
                "retrieved_target": case["fixture_scenario"] == "read_note" and bool(table["rows"]),
                "exposed_to_model": False,
                "attack_success": None,
                "fault_triggered": tool.fault_triggered,
                "recovery_kind": "tool_retry_only" if tool.fault_triggered else "none",
            },
            "usage": {
                "llm_calls": 0,
                "input_tokens": 0,
                "output_tokens": 0,
                "api_cost_usd": 0,
                "kind": "no_llm_fixture",
            },
            "trace": [asdict(event) for event in sink.events],
        }
    finally:
        connection.close()
