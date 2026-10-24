"""Agent runtime on the business policy: schema preflight, planner context and a full run.

Uses a generated SQLite file with the reviewed financial schema (tables, columns and foreign
keys), so the real ``financial.sqlite`` is never needed.
"""

import asyncio
import sqlite3

import pytest

from sqlguard.agent.controller import AgentController, RunScope
from sqlguard.agent.models import AgentRequest, RunStatus
from sqlguard.agent.planning import OllamaPlanner, Plan
from sqlguard.agent.runtime import QueryRuntimeError, build_query_runtime_factory
from sqlguard.mcp.tools import InProcessToolRegistry
from sqlguard.memory.semantic import BUSINESS_SEMANTIC_MEMORY, semantic_memory_for
from sqlguard.memory.store import InMemoryMemory
from sqlguard.observability.events import InMemoryEventSink
from sqlguard.security.gate import ReadOnlySQLGate
from sqlguard.security.policy import load_policy
from sqlguard.security.prompting import build_system_prompt
from sqlguard.security.schema_preflight import FINANCIAL_FOREIGN_KEYS, FINANCIAL_SCHEMA_CONTRACT

POLICY = load_policy("business_financial_v1")
ROLES = ("operator", "analyst", "credit_officer")


def create_financial_db(path, *, drop_column=None):
    references = {(t, c): (rt, rc) for t, c, rt, rc in FINANCIAL_FOREIGN_KEYS}
    canaries = {(c.table, c.column): c.value for c in POLICY.canaries}
    with sqlite3.connect(path) as connection:
        for table, columns in FINANCIAL_SCHEMA_CONTRACT.items():
            ordered = sorted(c for c in columns if c != drop_column)
            definitions = [f'"{c}"' for c in ordered] + [
                f'FOREIGN KEY ("{c}") REFERENCES "{references[(table, c)][0]}" '
                f'("{references[(table, c)][1]}")'
                for c in ordered
                if (table, c) in references
            ]
            connection.execute(f'CREATE TABLE "{table}" ({", ".join(definitions)})')
            for row in (1, 2, 3):
                values = [
                    canaries.get((table, c.casefold()), row if c.endswith("_id") else f"v{row}")
                    for c in ordered
                ]
                marks = ", ".join("?" for _ in ordered)
                connection.execute(f'INSERT INTO "{table}" VALUES ({marks})', values)
    connection.close()
    return path


@pytest.fixture
def env(tmp_path):
    path = create_financial_db(tmp_path / "financial.sqlite")
    return {"SQLGUARD_QUERY_SOURCE": "sqlite", "SQLGUARD_SQLITE_PATH": str(path)}


def test_runtime_accepts_the_reviewed_schema_for_every_business_role(env):
    for role in ROLES:
        factory = build_query_runtime_factory(role, env, policy=POLICY)
        assert factory.policy is POLICY and factory.role == role


def test_runtime_fails_closed_on_schema_drift(tmp_path):
    path = create_financial_db(tmp_path / "drift.sqlite", drop_column="address")
    env = {"SQLGUARD_QUERY_SOURCE": "sqlite", "SQLGUARD_SQLITE_PATH": str(path)}
    with pytest.raises(QueryRuntimeError) as raised:
        build_query_runtime_factory("operator", env, policy=POLICY)
    assert raised.value.category == "query_sqlite_schema_mismatch"


def test_runtime_rejects_roles_outside_the_business_policy(env):
    for role in ("teller", "admin", "sales"):
        with pytest.raises(QueryRuntimeError) as raised:
            build_query_runtime_factory(role, env, policy=POLICY)
        assert raised.value.category == "query_unknown_role"


class _FixedPlanner:
    def __init__(self, sql):
        self.sql = sql

    async def create_plan(self, question, context):
        return Plan(sql=self.sql, summary="fixed")


def run_agent(env, role, sql):
    factory = build_query_runtime_factory(role, env, policy=POLICY)

    def scope_factory(run_id):
        runtime = factory.for_run(run_id)
        return RunScope(
            runtime.gate,
            InProcessToolRegistry([runtime.tool]),
            output_check=runtime.output_check,
            output_check_policy_id=POLICY.version,
            output_check_enabled=True,
        )

    controller = AgentController(
        planner=_FixedPlanner(sql),
        tools=InProcessToolRegistry([]),
        security_gate=ReadOnlySQLGate(),
        memory=InMemoryMemory(),
        events=InMemoryEventSink(),
        run_scope_factory=scope_factory,
    )
    return asyncio.run(controller.run(AgentRequest("question"))).state


@pytest.mark.parametrize(
    ("role", "sql"),
    [
        ("analyst", "SELECT gender, COUNT(DISTINCT client_id) FROM client GROUP BY gender"),
        ("operator", "SELECT client_id, full_name, address FROM client"),
        ("credit_officer", "SELECT loan_id, amount, status FROM loan"),
    ],
)
def test_agent_runs_permitted_queries(env, role, sql):
    state = run_agent(env, role, sql)
    assert state.status is RunStatus.SUCCEEDED, state.failure_reason


@pytest.mark.parametrize(
    ("role", "sql"),
    [
        ("analyst", "SELECT client_id, gender FROM client"),
        ("analyst", "SELECT COUNT(*) FROM trans GROUP BY account_id"),
        ("operator", "SELECT amount FROM loan"),
        ("operator", "SELECT client_id FROM client WHERE id_number = 'CANARY-ID-0001'"),
        ("credit_officer", "SELECT client_id FROM client ORDER BY address"),
    ],
)
def test_agent_refuses_forbidden_queries(env, role, sql):
    state = run_agent(env, role, sql)
    assert state.status is RunStatus.REFUSED
    assert state.final_answer is None


def test_partial_answer_never_carries_a_canary(env):
    state = run_agent(env, "operator", "SELECT client_id, id_number FROM client")
    assert state.status is RunStatus.SUCCEEDED
    assert "CANARY" not in (state.final_answer or "")


# -- planner context ---------------------------------------------------------------------------


def test_business_policy_has_its_own_semantic_catalog():
    assert semantic_memory_for(POLICY) is BUSINESS_SEMANTIC_MEMORY
    visible = {
        role: {d.definition_id for d in BUSINESS_SEMANTIC_MEMORY.for_role(role, POLICY)}
        for role in ROLES
    }
    assert "loan.status-codes" in visible["credit_officer"]
    assert "loan.status-codes" not in visible["operator"] | visible["analyst"]
    assert "trans.balance-after" not in visible["analyst"]
    assert semantic_memory_for(load_policy("bird_financial_v1")) is None


@pytest.mark.parametrize("role", ROLES)
def test_ollama_planner_accepts_the_business_policy(role):
    planner = OllamaPlanner(policy=POLICY, role=role)
    assert planner.model


def test_system_prompt_describes_sqlite_and_the_aggregate_rules():
    analyst = build_system_prompt(POLICY, "analyst")
    operator = build_system_prompt(POLICY, "operator")
    assert "write SQLite SELECT queries" in analyst
    assert "aggregate results only" in analyst and "[key]" in analyst
    assert "aggregate results only" not in operator
    assert "id_number" not in analyst + operator and "placeholder" not in analyst + operator
    synthetic = build_system_prompt(load_policy("d2_synthetic_v1"), "sales")
    assert "write PostgreSQL SELECT queries" in synthetic
