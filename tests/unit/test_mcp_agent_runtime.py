import asyncio
import sqlite3
from types import SimpleNamespace

import pytest
from tests.security.fakes import StaticExecutor

from sqlguard import demo
from sqlguard.agent.models import ExecutionBudget, RunStatus
from sqlguard.agent.planning import Plan
from sqlguard.agent.runtime import QueryRuntimeError, build_query_runtime_factory
from sqlguard.mcp.client import McpToolRegistry

ALLOWED_SQL = "SELECT order_id, total_amount_vnd FROM orders ORDER BY order_id LIMIT 2"
SQLITE_ENV = {
    "SQLGUARD_MCP_ENABLED": "true",
    "SQLGUARD_QUERY_SOURCE": "sqlite",
    "SQLGUARD_ROLE": "sales",
}


class FixedPlanner:
    def __init__(self, sql=ALLOWED_SQL):
        self.sql = sql

    async def create_plan(self, question, context):
        return Plan(sql=self.sql, summary="fixed")


class FakeSession:
    def __init__(self, *, delay=0, error=None, result="ok"):
        self.delay = delay
        self.error = error
        self.result = result
        self.calls = []
        self.tools = [
            SimpleNamespace(
                name=name,
                input_schema={"type": "object"},
                output_schema=None,
            )
            for name in ("query", "get_schema", "unexpected_admin_tool")
        ]

    async def list_tools(self):
        return SimpleNamespace(tools=self.tools)

    async def call_tool(self, name, arguments):
        self.calls.append((name, arguments))
        if self.delay:
            await asyncio.sleep(self.delay)
        if self.error:
            raise self.error
        if isinstance(self.result, Exception):
            raise self.result
        return self.result


class FakeConnection:
    def __init__(self, session, *, enter_error=None, registry_error=None):
        self.session = session
        self.enter_error = enter_error
        self.registry_error = registry_error
        self.entered = False
        self.closed = False

    async def __aenter__(self):
        if self.enter_error:
            self.closed = True
            raise self.enter_error
        self.entered = True
        return self

    async def __aexit__(self, *exc_info):
        self.closed = True

    async def registry(self):
        if self.registry_error:
            raise self.registry_error
        return await McpToolRegistry.discover(self.session, allowed={"query", "get_schema"})


@pytest.fixture
def sqlite_db(tmp_path):
    path = tmp_path / "agent.db"
    with sqlite3.connect(path) as connection:
        connection.execute(
            "CREATE TABLE orders (order_id INTEGER, total_amount_vnd INTEGER, customer_id INTEGER)"
        )
        connection.execute("INSERT INTO orders VALUES (1, 100, 10)")
    return path


@pytest.fixture
def configure_mcp(monkeypatch, sqlite_db):
    for key, value in SQLITE_ENV.items():
        monkeypatch.setenv(key, value)
    monkeypatch.setenv("SQLGUARD_SQLITE_PATH", str(sqlite_db))
    return sqlite_db


def make_factory(db, role="sales"):
    return build_query_runtime_factory(
        role,
        {**SQLITE_ENV, "SQLGUARD_SQLITE_PATH": str(db)},
        executor=StaticExecutor(("order_id",), [(1,)]),
    )


def mcp_result():
    return SimpleNamespace(
        is_error=False,
        structured_content={
            "source": "database",
            "trust": "untrusted",
            "columns": ["order_id"],
            "rows": [[1]],
            "row_count": 1,
            "truncated": False,
        },
        content=[],
    )


def install_connection(monkeypatch, connection):
    monkeypatch.setattr(demo, "sqlite_server_connection", lambda *args, **kwargs: connection)


def test_controller_calls_mcp_after_gate_and_closes_connection(monkeypatch, configure_mcp):
    session = FakeSession(result=mcp_result())
    connection = FakeConnection(session)
    install_connection(monkeypatch, connection)

    report = asyncio.run(
        demo.run_demo_report(FixedPlanner(), query_factory=make_factory(configure_mcp))
    )

    assert report.succeeded
    assert report.query_source == "mcp"
    assert report.gate_checks[0].allowed
    assert session.calls == [("query", {"sql": ALLOWED_SQL})]
    assert connection.entered and connection.closed


def test_rejected_sql_never_reaches_mcp_query_tool(monkeypatch, configure_mcp):
    session = FakeSession(result=mcp_result())
    connection = FakeConnection(session)
    install_connection(monkeypatch, connection)

    report = asyncio.run(
        demo.run_demo_report(
            FixedPlanner("DELETE FROM orders"), query_factory=make_factory(configure_mcp)
        )
    )

    assert report.status == RunStatus.REFUSED
    assert report.failure_reason == "security_rejection"
    assert not session.calls
    assert connection.closed


def test_unapproved_server_tool_is_never_registered_or_called(monkeypatch, configure_mcp):
    session = FakeSession(result=mcp_result())
    connection = FakeConnection(session)
    install_connection(monkeypatch, connection)

    report = asyncio.run(
        demo.run_demo_report(FixedPlanner(), query_factory=make_factory(configure_mcp))
    )

    assert report.succeeded
    assert all(name != "unexpected_admin_tool" for name, _ in session.calls)
    assert [name for name, _ in session.calls] == ["query"]


@pytest.mark.parametrize(
    ("updates", "category"),
    [
        ({"SQLGUARD_QUERY_SOURCE": "postgres"}, "mcp_requires_sqlite"),
        ({"SQLGUARD_ROLE": ""}, "query_role_missing"),
        ({"SQLGUARD_SQLITE_PATH": ""}, "query_sqlite_path_missing"),
    ],
)
def test_invalid_mcp_configuration_fails_before_connect(
    monkeypatch, configure_mcp, updates, category
):
    for key, value in updates.items():
        monkeypatch.setenv(key, value)
    connection = FakeConnection(FakeSession())
    install_connection(monkeypatch, connection)

    with pytest.raises(QueryRuntimeError) as info:
        asyncio.run(demo.run_demo_report(FixedPlanner()))

    assert info.value.category == category
    assert not connection.entered


def test_connection_start_failure_does_not_fallback_to_mock(monkeypatch, configure_mcp):
    connection = FakeConnection(FakeSession(), enter_error=OSError("private transport detail"))
    install_connection(monkeypatch, connection)

    with pytest.raises(QueryRuntimeError) as info:
        asyncio.run(demo.run_demo_report(FixedPlanner()))

    assert info.value.category == "mcp_connection_failed"
    assert "private" not in str(info.value)
    assert not connection.entered
    assert connection.closed


def test_discovery_failure_closes_connection_and_fails_closed(monkeypatch, configure_mcp):
    connection = FakeConnection(FakeSession(), registry_error=RuntimeError("private details"))
    install_connection(monkeypatch, connection)

    with pytest.raises(QueryRuntimeError) as info:
        asyncio.run(demo.run_demo_report(FixedPlanner()))

    assert info.value.category == "mcp_discovery_failed"
    assert "private" not in str(info.value)
    assert connection.closed


def test_transport_error_is_normalized_and_connection_closed(monkeypatch, configure_mcp):
    session = FakeSession(error=OSError("host=private.internal"))
    connection = FakeConnection(session)
    install_connection(monkeypatch, connection)

    report = asyncio.run(
        demo.run_demo_report(FixedPlanner(), query_factory=make_factory(configure_mcp))
    )

    assert not report.succeeded
    assert report.failure_reason == "mcp_transport_error"
    assert "private" not in report.failure_reason
    assert connection.closed


def test_timeout_is_handled_and_connection_closed(monkeypatch, configure_mcp):
    session = FakeSession(delay=0.1, result=mcp_result())
    connection = FakeConnection(session)
    install_connection(monkeypatch, connection)

    report = asyncio.run(
        demo.run_demo_report(
            FixedPlanner(),
            query_factory=make_factory(configure_mcp),
            budget=ExecutionBudget(
                max_retries=0,
                query_timeout_seconds=0.01,
                run_timeout_seconds=1,
            ),
        )
    )

    assert not report.succeeded
    assert report.failure_reason == "tool_timeout"
    assert connection.closed


def test_malformed_mcp_response_fails_safely_and_closes_connection(monkeypatch, configure_mcp):
    session = FakeSession(
        result=SimpleNamespace(is_error=False, structured_content="not an object", content=[])
    )
    connection = FakeConnection(session)
    install_connection(monkeypatch, connection)

    report = asyncio.run(
        demo.run_demo_report(FixedPlanner(), query_factory=make_factory(configure_mcp))
    )

    assert not report.succeeded
    assert report.failure_reason == "mcp_invalid_result"
    assert connection.closed


def test_mcp_disabled_preserves_mock_mode(monkeypatch):
    monkeypatch.delenv("SQLGUARD_MCP_ENABLED", raising=False)
    monkeypatch.delenv("SQLGUARD_QUERY_SOURCE", raising=False)
    monkeypatch.delenv("SQLGUARD_ROLE", raising=False)
    report = asyncio.run(demo.run_demo_report(FixedPlanner()))
    assert report.succeeded
    assert report.query_source == "mock"


def test_mcp_uses_configured_sqlite_runtime_without_injected_factory(monkeypatch, configure_mcp):
    connection = FakeConnection(FakeSession(result=mcp_result()))
    install_connection(monkeypatch, connection)

    report = asyncio.run(demo.run_demo_report(FixedPlanner()))

    assert report.succeeded
    assert report.query_source == "mcp"
    assert connection.closed


def test_mcp_expands_sqlite_path_before_validation_and_connection(monkeypatch, configure_mcp):
    database = configure_mcp
    monkeypatch.setenv("HOME", str(database.parent))
    monkeypatch.setenv("SQLGUARD_SQLITE_PATH", "~/agent.db")
    connection = FakeConnection(FakeSession(result=mcp_result()))
    received = {}

    def connection_factory(path, role, **kwargs):
        received["path"] = path
        received["role"] = role
        return connection

    monkeypatch.setattr(demo, "sqlite_server_connection", connection_factory)
    report = asyncio.run(demo.run_demo_report(FixedPlanner()))

    assert report.succeeded
    assert received == {"path": str(database), "role": "sales"}
    assert connection.closed


def test_cancellation_closes_mcp_connection(monkeypatch, configure_mcp):
    session = FakeSession(delay=10, result=mcp_result())
    connection = FakeConnection(session)
    install_connection(monkeypatch, connection)

    async def scenario():
        task = asyncio.create_task(
            demo.run_demo_report(FixedPlanner(), query_factory=make_factory(configure_mcp))
        )
        while not session.calls:
            await asyncio.sleep(0.001)
        task.cancel()
        with pytest.raises(asyncio.CancelledError):
            await task

    asyncio.run(scenario())
    assert connection.closed


def test_invalid_mcp_flag_does_not_silently_disable(monkeypatch):
    monkeypatch.setenv("SQLGUARD_MCP_ENABLED", "sometimes")
    with pytest.raises(QueryRuntimeError) as info:
        asyncio.run(demo.run_demo_report(FixedPlanner()))
    assert info.value.category == "mcp_invalid_config"
