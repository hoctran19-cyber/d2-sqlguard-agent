import sqlite3

import pytest

from sqlguard.agent.controller import AgentController
from sqlguard.agent.models import ExecutionBudget
from sqlguard.agent.planning import DemoPlanner
from sqlguard.mcp.tools import InProcessToolRegistry, MockQueryTool
from sqlguard.memory.store import InMemoryMemory
from sqlguard.observability.events import InMemoryEventSink
from sqlguard.security.business_database import BUSINESS_DATABASE_ENV
from sqlguard.security.gate import ReadOnlySQLGate
from sqlguard.security.policy import load_policy
from sqlguard.security.schema_preflight import FINANCIAL_FOREIGN_KEYS, FINANCIAL_SCHEMA_CONTRACT


@pytest.fixture(autouse=True)
def _no_business_database_from_the_shell(monkeypatch):
    # A developer's SQLGUARD_BUSINESS_FINANCIAL_DB must not switch business roles on in tests.
    monkeypatch.delenv(BUSINESS_DATABASE_ENV, raising=False)


def create_financial_db(path, *, drop_column=None):
    """SQLite file with the reviewed financial schema (columns and foreign keys), three rows per
    table and the business policy canaries; never the real ``financial.sqlite``."""
    canaries = {(c.table, c.column): c.value for c in load_policy("business_financial_v1").canaries}
    references = {(t, c): (rt, rc) for t, c, rt, rc in FINANCIAL_FOREIGN_KEYS}
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
def financial_db(tmp_path):
    return create_financial_db(tmp_path / "financial.sqlite")


def make_controller(
    *,
    tool=None,
    planner=None,
    gate=None,
    memory=None,
    events=None,
    budget=None,
    run_scope_factory=None,
) -> AgentController:
    return AgentController(
        planner=planner or DemoPlanner(),
        tools=InProcessToolRegistry([tool or MockQueryTool()]),
        security_gate=gate or ReadOnlySQLGate(),
        memory=memory or InMemoryMemory(),
        events=events or InMemoryEventSink(),
        budget=budget or ExecutionBudget(),
        run_scope_factory=run_scope_factory,
    )
