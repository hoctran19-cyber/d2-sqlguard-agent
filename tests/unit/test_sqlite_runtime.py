import asyncio
import sqlite3

import pytest

from sqlguard.agent.planning import OllamaPlanner
from sqlguard.agent.postgres_schema import SchemaAdapterError
from sqlguard.agent.runtime import (
    QueryRuntimeError,
    build_query_runtime_factory,
    create_planner_for_role,
)
from sqlguard.agent.sqlite_schema import SQLiteSchemaAdapter
from sqlguard.mcp.tools import MockQueryTool
from sqlguard.security.service import ExecutorError, QueryResult
from sqlguard.security.sqlite import SQLiteExecutor

SQLITE_ENV = {"SQLGUARD_QUERY_SOURCE": "sqlite"}
ALLOWED_SQL = "SELECT order_id, total_amount_vnd FROM orders ORDER BY order_id LIMIT 2"


@pytest.fixture
def sqlite_path(tmp_path):
    path = tmp_path / "runtime.db"
    with sqlite3.connect(path) as connection:
        connection.executescript(
            """
            CREATE TABLE orders (
                order_id INTEGER,
                customer_id INTEGER,
                order_date TEXT,
                status TEXT,
                channel TEXT,
                total_amount_vnd INTEGER,
                note TEXT
            );
            INSERT INTO orders VALUES
                (1, 10, '2025-01-01', 'completed', 'web', 1200, 'first'),
                (2, 11, '2025-01-02', 'completed', 'store', 2300, 'second');
            CREATE TABLE customers (
                customer_id INTEGER,
                full_name TEXT,
                city TEXT,
                segment TEXT,
                created_at TEXT,
                phone_number TEXT,
                identity_number TEXT,
                note TEXT
            );
            CREATE TABLE payments (
                payment_id INTEGER,
                order_id INTEGER,
                amount_vnd INTEGER,
                bank_reference TEXT
            );
            CREATE TABLE secret_table (secret TEXT);
            """
        )
    return path


def test_sqlite_runtime_executes_allowed_sql_through_secure_tool(sqlite_path):
    env = {**SQLITE_ENV, "SQLGUARD_SQLITE_PATH": str(sqlite_path)}
    factory = build_query_runtime_factory("sales", env)

    assert factory is not None
    assert factory.source == "sqlite"
    assert isinstance(factory.executor, SQLiteExecutor)
    runtime = factory.for_run("sqlite-test")
    assert not isinstance(runtime.tool, MockQueryTool)

    result = asyncio.run(runtime.tool.call({"sql": ALLOWED_SQL}, timeout_seconds=5))

    assert result["source"] == "database"
    assert result["rows"] == [[1, 1200], [2, 2300]]
    assert result["trust"] == "untrusted"


def test_denied_sql_never_reaches_sqlite_executor(sqlite_path):
    class RecordingExecutor:
        def __init__(self):
            self.calls = []

        async def execute(self, sql, *, role, timeout_seconds, max_rows):
            self.calls.append((sql, role))
            return QueryResult(columns=(), rows=())

    executor = RecordingExecutor()
    factory = build_query_runtime_factory(
        "sales",
        {**SQLITE_ENV, "SQLGUARD_SQLITE_PATH": str(sqlite_path)},
        executor=executor,
    )
    runtime = factory.for_run("denial-test")

    with pytest.raises(Exception) as caught:
        asyncio.run(runtime.tool.call({"sql": "DELETE FROM orders"}, timeout_seconds=5))

    assert getattr(caught.value, "category", None) == "security_rejection"
    assert executor.calls == []


def test_sqlite_executor_is_read_only_and_bounds_fetches(sqlite_path):
    executor = SQLiteExecutor(sqlite_path)
    rows = asyncio.run(
        executor.execute(
            "SELECT order_id FROM orders ORDER BY order_id",
            role="sales",
            timeout_seconds=5,
            max_rows=1,
        )
    )
    assert rows.rows == ((1,), (2,))

    with pytest.raises(ExecutorError) as caught:
        asyncio.run(
            executor.execute(
                "DELETE FROM orders",
                role="sales",
                timeout_seconds=5,
                max_rows=1,
            )
        )
    # Authorizer chặn DELETE lúc prepare, trước cả mode=ro.
    assert caught.value.category == "db_permission_denied"


def test_sqlite_schema_is_filtered_by_role_policy(sqlite_path):
    schema = SQLiteSchemaAdapter(sqlite_path).load_sync("sales")

    tables = {table.name: {column.name for column in table.columns} for table in schema.tables}
    assert schema.dialect == "sqlite"
    assert "secret_table" not in tables
    assert "phone_number" not in tables["customers"]
    assert "identity_number" not in tables["customers"]
    assert "bank_reference" not in tables["payments"]
    assert "total_amount_vnd" in tables["orders"]


def test_sqlite_schema_source_is_wired_to_ollama_planner(sqlite_path):
    env = {
        "SQLGUARD_PLANNER": "ollama",
        "SQLGUARD_SCHEMA_SOURCE": "sqlite",
        "SQLGUARD_SQLITE_PATH": str(sqlite_path),
    }

    planner = asyncio.run(create_planner_for_role("sales", env))

    assert isinstance(planner, OllamaPlanner)
    assert planner.schema_context is not None
    assert planner.schema_context.dialect == "sqlite"
    assert "phone_number" not in planner.schema_context.to_prompt_text()


@pytest.mark.parametrize(
    ("env", "category"),
    [
        (SQLITE_ENV, "query_sqlite_path_missing"),
        (
            {**SQLITE_ENV, "SQLGUARD_SQLITE_PATH": "/missing/sqlguard.db"},
            "query_sqlite_db_missing",
        ),
    ],
)
def test_sqlite_query_configuration_fails_closed(env, category):
    with pytest.raises(QueryRuntimeError) as caught:
        build_query_runtime_factory("sales", env)
    assert caught.value.category == category


def test_sqlite_schema_configuration_fails_closed_for_missing_database():
    with pytest.raises(SchemaAdapterError) as caught:
        SQLiteSchemaAdapter.from_env(env={"SQLGUARD_SQLITE_PATH": "/missing/sqlguard.db"})
    assert caught.value.category == "schema_sqlite_db_missing"


def test_postgres_query_configuration_remains_available():
    class RecordingExecutor:
        async def execute(self, sql, *, role, timeout_seconds, max_rows):
            return QueryResult(columns=("order_id",), rows=((1,),))

    factory = build_query_runtime_factory(
        "sales",
        {
            "SQLGUARD_QUERY_SOURCE": "postgres",
            "SQLGUARD_DB_DSN_SALES": "postgresql://local-test",
        },
        executor=RecordingExecutor(),
    )

    assert factory is not None
    assert factory.source == "postgres"
    result = asyncio.run(
        factory.for_run("postgres-regression").tool.call(
            {"sql": "SELECT order_id FROM orders LIMIT 1"}, timeout_seconds=5
        )
    )
    assert result["rows"] == [[1]]
