import asyncio
import io
import json
import sqlite3
import urllib.error

import pytest
from tests.security.fakes import StaticExecutor

from sqlguard import demo, demo_fixture
from sqlguard.agent.planning import Plan
from sqlguard.agent.postgres_schema import SchemaAdapterError
from sqlguard.agent.runtime import QueryRuntimeError, build_query_runtime_factory
from sqlguard.agent.sqlite_schema import SQLiteSchemaAdapter
from sqlguard.demo_fixture import create_demo_database
from sqlguard.security.policy import load_default_policy

QUESTION = "List order IDs and total amounts"
ALLOWED_SQL = "SELECT order_id, total_amount_vnd FROM orders ORDER BY order_id"


class FixedPlanner:
    def __init__(self, sql=ALLOWED_SQL):
        self.sql = sql

    async def create_plan(self, question, context):
        return Plan(sql=self.sql, summary="fixed")


class RecordingExecutor(StaticExecutor):
    def __init__(self):
        super().__init__(("order_id", "total_amount_vnd"), [(101, 120000), (102, 230000)])


class FakeResponse(io.BytesIO):
    def __enter__(self):
        return self

    def __exit__(self, *args):
        self.close()


def configure_sqlite_demo(monkeypatch, database):
    monkeypatch.setenv("SQLGUARD_POLICY", "d2_synthetic_v1")
    monkeypatch.setenv("SQLGUARD_PLANNER", "ollama")
    monkeypatch.setenv("SQLGUARD_OLLAMA_MODEL", "qwen3:1.7b")
    monkeypatch.setenv("SQLGUARD_SCHEMA_SOURCE", "sqlite")
    monkeypatch.setenv("SQLGUARD_QUERY_SOURCE", "sqlite")
    monkeypatch.setenv("SQLGUARD_SQLITE_PATH", str(database))
    monkeypatch.setenv("SQLGUARD_ROLE", "sales")
    monkeypatch.delenv("SQLGUARD_MCP_ENABLED", raising=False)


@pytest.fixture
def demo_db(tmp_path):
    return create_demo_database(tmp_path / "synthetic-demo.sqlite")


def test_fixture_matches_synthetic_policy_and_has_only_synthetic_demo_data(demo_db):
    policy = load_default_policy()
    with sqlite3.connect(demo_db) as connection:
        tables = {
            name: {row[1].casefold() for row in connection.execute(f'PRAGMA table_info("{name}")')}
            for (name,) in connection.execute(
                "SELECT name FROM sqlite_master WHERE type = 'table' AND name NOT LIKE 'sqlite_%'"
            )
        }
        foreign_keys = {
            frozenset(((table, row[3].casefold()), (row[2].casefold(), row[4].casefold())))
            for table in tables
            for row in connection.execute(f'PRAGMA foreign_key_list("{table}")')
        }
        actual_rows = connection.execute(
            "SELECT order_id, total_amount_vnd FROM orders ORDER BY order_id"
        ).fetchall()

    assert tables == policy.tables
    assert foreign_keys == policy.foreign_keys
    assert actual_rows == [(101, 120000), (102, 230000)]
    schema = SQLiteSchemaAdapter(demo_db, policy).load_sync("sales")
    visible = {table.name: {column.name for column in table.columns} for table in schema.tables}
    assert set(visible) == set(policy.allowed_tables("sales"))
    assert "identity_number" not in visible["customers"]
    assert "phone_number" not in visible["customers"]
    assert "bank_reference" not in visible["payments"]


def test_ollama_schema_and_sqlite_execution_use_same_real_database(demo_db, monkeypatch):
    configure_sqlite_demo(monkeypatch, demo_db)
    requests = []

    def fake_urlopen(request, timeout=None):
        payload = json.loads(request.data)
        requests.append(payload)
        body = json.dumps(
            {
                "message": {
                    "content": json.dumps({"sql": ALLOWED_SQL, "summary": "List demo orders"})
                }
            }
        )
        return FakeResponse(body.encode())

    monkeypatch.setattr("sqlguard.agent.planning.urllib.request.urlopen", fake_urlopen)
    report = asyncio.run(demo.run_demo_report(question=QUESTION))

    assert report.succeeded
    assert report.planner == "ollama"
    assert report.model == "qwen3:1.7b"
    assert report.query_source == "sqlite"
    assert report.schema_dialect == "sqlite"
    assert report.schema_tables == 5
    assert report.gate_checks[0].allowed
    assert report.tool_sql == [report.gate_checks[0].sql]
    assert "101" in report.final_answer
    assert "120000" in report.final_answer
    assert "102" in report.final_answer
    assert "230000" in report.final_answer
    assert len(requests) == 1
    prompt = requests[0]["messages"][1]["content"]
    assert QUESTION in prompt
    assert "Table: orders" in prompt
    assert "total_amount_vnd" in prompt
    assert "identity_number" not in prompt
    assert "phone_number" not in prompt
    assert "bank_reference" not in prompt


@pytest.mark.parametrize(
    "sql",
    [
        "INSERT INTO orders (order_id) VALUES (103)",
        "UPDATE orders SET status = 'cancelled'",
        "DELETE FROM orders",
        "SELECT order_id FROM orders; SELECT order_id FROM orders",
        "SELECT identity_number FROM customers",
    ],
)
def test_rejected_sql_never_reaches_executor(sql, demo_db, monkeypatch):
    monkeypatch.setenv("SQLGUARD_ROLE", "sales")
    executor = RecordingExecutor()
    factory = build_query_runtime_factory(
        "sales",
        {
            "SQLGUARD_QUERY_SOURCE": "sqlite",
            "SQLGUARD_SQLITE_PATH": str(demo_db),
            "SQLGUARD_POLICY": "d2_synthetic_v1",
        },
        executor=executor,
    )

    report = asyncio.run(
        demo.run_demo_report(FixedPlanner(sql), query_factory=factory, question=QUESTION)
    )

    assert not report.succeeded
    assert report.failure_reason == "security_rejection"
    assert report.gate_checks and not report.gate_checks[0].allowed
    assert report.tool_sql == []
    assert executor.calls == []


@pytest.mark.parametrize(
    ("role", "path", "category"),
    [
        ("sales", None, "query_sqlite_path_missing"),
        ("sales", "/missing/sqlguard-demo.sqlite", "query_sqlite_db_missing"),
        (None, "/tmp/unused-sqlguard-demo.sqlite", "query_role_missing"),
        ("operator", "/tmp/unused-sqlguard-demo.sqlite", "query_unknown_role"),
        ("analyst", "/tmp/unused-sqlguard-demo.sqlite", "query_unknown_role"),
        ("credit_officer", "/tmp/unused-sqlguard-demo.sqlite", "query_unknown_role"),
    ],
)
def test_missing_or_unapproved_runtime_configuration_fails_closed(role, path, category):
    env = {"SQLGUARD_QUERY_SOURCE": "sqlite", "SQLGUARD_POLICY": "d2_synthetic_v1"}
    if path is not None:
        env["SQLGUARD_SQLITE_PATH"] = path
    with pytest.raises(QueryRuntimeError) as caught:
        build_query_runtime_factory(role, env)
    assert caught.value.category == category


def test_missing_sqlite_path_does_not_use_legacy_database(monkeypatch, demo_db):
    monkeypatch.setenv("SQLGUARD_FINANCIAL_DB", str(demo_db))
    with pytest.raises(QueryRuntimeError) as caught:
        build_query_runtime_factory(
            "sales",
            {"SQLGUARD_QUERY_SOURCE": "sqlite", "SQLGUARD_POLICY": "d2_synthetic_v1"},
        )
    assert caught.value.category == "query_sqlite_path_missing"


def test_demo_missing_sqlite_configuration_does_not_fall_back_to_mock(monkeypatch, demo_db):
    monkeypatch.setenv("SQLGUARD_QUERY_SOURCE", "sqlite")
    monkeypatch.setenv("SQLGUARD_ROLE", "sales")
    monkeypatch.setenv("SQLGUARD_FINANCIAL_DB", str(demo_db))
    monkeypatch.delenv("SQLGUARD_SQLITE_PATH", raising=False)
    monkeypatch.delenv("SQLGUARD_PLANNER", raising=False)

    with pytest.raises(QueryRuntimeError) as caught:
        asyncio.run(demo.run_demo_report())

    assert caught.value.category == "query_sqlite_path_missing"


def test_invalid_sqlite_schema_fails_before_planner_or_mock(demo_db, monkeypatch):
    configure_sqlite_demo(monkeypatch, demo_db)
    invalid_db = demo_db.parent / "not-sqlite.sqlite"
    invalid_db.write_text("not a database", encoding="utf-8")
    monkeypatch.setenv("SQLGUARD_SQLITE_PATH", str(invalid_db))
    ollama_calls = []
    monkeypatch.setattr(
        "sqlguard.agent.planning.urllib.request.urlopen",
        lambda *args, **kwargs: ollama_calls.append(args),
    )

    with pytest.raises(SchemaAdapterError) as caught:
        asyncio.run(demo.run_demo_report(question=QUESTION))

    assert caught.value.category == "schema_sqlite_error"
    assert str(invalid_db) not in str(caught.value)
    assert ollama_calls == []


def test_empty_sqlite_schema_fails_before_planner_or_mock(demo_db, monkeypatch):
    configure_sqlite_demo(monkeypatch, demo_db)
    empty_db = demo_db.parent / "empty.sqlite"
    with sqlite3.connect(empty_db):
        pass
    monkeypatch.setenv("SQLGUARD_SQLITE_PATH", str(empty_db))
    ollama_calls = []
    monkeypatch.setattr(
        "sqlguard.agent.planning.urllib.request.urlopen",
        lambda *args, **kwargs: ollama_calls.append(args),
    )

    with pytest.raises(SchemaAdapterError) as caught:
        asyncio.run(demo.run_demo_report(question=QUESTION))

    assert caught.value.category == "schema_empty"
    assert str(empty_db) not in str(caught.value)
    assert ollama_calls == []


def test_ollama_sqlite_requires_schema_source_configuration(demo_db, monkeypatch):
    configure_sqlite_demo(monkeypatch, demo_db)
    monkeypatch.delenv("SQLGUARD_SCHEMA_SOURCE")
    ollama_calls = []
    monkeypatch.setattr(
        "sqlguard.agent.planning.urllib.request.urlopen",
        lambda *args, **kwargs: ollama_calls.append(args),
    )

    with pytest.raises(SchemaAdapterError) as caught:
        asyncio.run(demo.run_demo_report(question=QUESTION))

    assert caught.value.category == "schema_sqlite_source_required"
    assert ollama_calls == []


def test_missing_business_roles_do_not_become_authorized_by_schema(demo_db, monkeypatch):
    configure_sqlite_demo(monkeypatch, demo_db)
    for role in ("operator", "analyst", "credit_officer"):
        monkeypatch.setenv("SQLGUARD_ROLE", role)
        with pytest.raises(QueryRuntimeError) as caught:
            asyncio.run(demo.run_demo_report(question=QUESTION))
        assert caught.value.category == "query_unknown_role"


def test_ollama_unavailable_does_not_fall_back_to_mock(demo_db, monkeypatch):
    configure_sqlite_demo(monkeypatch, demo_db)

    def unavailable(*args, **kwargs):
        raise urllib.error.URLError("private local endpoint detail")

    monkeypatch.setattr("sqlguard.agent.planning.urllib.request.urlopen", unavailable)
    report = asyncio.run(demo.run_demo_report(question=QUESTION))

    assert not report.succeeded
    assert report.failure_reason == "planner_error"
    assert report.final_answer is None
    assert report.tool_sql == []
    assert "mock_result" not in demo.format_report(report)
    assert "private" not in demo.format_report(report)


def test_fixture_generator_does_not_overwrite_existing_file(demo_db):
    with pytest.raises(FileExistsError, match="output file already exists"):
        create_demo_database(demo_db)


def test_fixture_generator_cli_creates_a_new_database(tmp_path, capsys):
    database = tmp_path / "cli-demo.sqlite"

    assert demo_fixture.main(["--output", str(database)]) == 0
    assert database.is_file()
    assert capsys.readouterr().out == "Created synthetic SQLGuard demo database.\n"


def test_cli_question_is_forwarded(monkeypatch, capsys):
    captured = {}

    async def fake_run_demo_report(*, question):
        captured["question"] = question
        return demo.DemoReport(
            planner="demo",
            model=None,
            succeeded=True,
            status="succeeded",
            failure_reason=None,
            final_answer="demo_value=1",
        )

    monkeypatch.setattr(demo, "run_demo_report", fake_run_demo_report)

    assert demo.main(["--question", QUESTION]) == 0
    assert captured["question"] == QUESTION
    assert "mock_result: demo_value=1" in capsys.readouterr().out
