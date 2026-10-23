import asyncio
import io
import json
import sqlite3
import urllib.error
from datetime import UTC, datetime
from uuid import uuid4

import pytest

pytest.importorskip("fastapi")
pytest.importorskip("httpx")

from fastapi.testclient import TestClient  # noqa: E402

from sqlguard.agent.runtime import build_query_runtime  # noqa: E402
from sqlguard.agent.sqlite_schema import SQLiteSchemaAdapter  # noqa: E402
from sqlguard.demo_fixture import create_demo_database  # noqa: E402
from sqlguard.observability.events import EVENT_DB_PATH_ENV, SQLiteEventStore  # noqa: E402
from sqlguard.security.policy import load_policy  # noqa: E402
from sqlguard.security.service import (  # noqa: E402
    ExecutorError,
    QueryResult,
    SecurityToolError,
)
from sqlguard.security.sqlite import SQLiteExecutor  # noqa: E402
from sqlguard.web.app import create_app  # noqa: E402
from sqlguard.web.query_service import (  # noqa: E402
    SYNTHETIC_POLICY_NAME,
    SYNTHETIC_QUESTION,
    SYNTHETIC_ROLE,
)

ALLOWED_SQL = "SELECT order_id, total_amount_vnd FROM orders ORDER BY order_id"


def assert_event_contract(body, terminal_type, terminal_status, terminal_error=None):
    events = body["events"]
    assert events[0]["event_type"] == "run_started"
    assert events[-1]["event_type"] == terminal_type
    assert events[-1]["status"] == terminal_status
    assert events[-1]["error_category"] == terminal_error
    assert all(event["run_id"] == body["run_id"] for event in events)
    for event in events:
        assert {
            "run_id",
            "event_type",
            "timestamp",
            "status",
            "duration_ms",
            "error_category",
        } <= event.keys()
        assert event["type"] == event["event_type"]
        timestamp = datetime.fromisoformat(event["timestamp"])
        assert timestamp.tzinfo is not None
        assert timestamp.utcoffset() == UTC.utcoffset(timestamp)
        assert event["duration_ms"] is None or event["duration_ms"] >= 0


class FakeResponse(io.BytesIO):
    def __enter__(self):
        return self

    def __exit__(self, *args):
        self.close()


@pytest.fixture
def web_db(tmp_path):
    return create_demo_database(tmp_path / "synthetic.sqlite")


@pytest.fixture
def legacy_db(tmp_path):
    path = tmp_path / "financial.sqlite"
    with sqlite3.connect(path) as connection:
        connection.executescript(
            "CREATE TABLE client (client_id INTEGER PRIMARY KEY);"
            "INSERT INTO client VALUES (1), (2);"
        )
    return path


@pytest.fixture
def web_client(web_db, monkeypatch):
    monkeypatch.setenv("SQLGUARD_WEB_QUERY_MODE", "synthetic_sqlite")
    monkeypatch.setenv("SQLGUARD_WEB_DEMO_SQLITE_PATH", str(web_db))
    monkeypatch.setenv("SQLGUARD_PLANNER", "ollama")
    monkeypatch.setenv("SQLGUARD_OLLAMA_MODEL", "qwen3:1.7b")
    monkeypatch.setenv("SQLGUARD_OLLAMA_TIMEOUT_SECONDS", "4")
    monkeypatch.setenv(EVENT_DB_PATH_ENV, str(web_db.parent / "events.sqlite3"))
    client = TestClient(create_app(web_db))
    assert (
        client.post("/api/login", json={"username": "admin", "password": "123456"}).status_code
        == 200
    )
    return client


def install_ollama(monkeypatch, sql=ALLOWED_SQL, *, failure=None):
    requests = []

    def fake_urlopen(request, timeout=None):
        requests.append((json.loads(request.data), timeout))
        if failure is not None:
            raise failure
        content = json.dumps({"sql": sql, "summary": "query orders"})
        body = json.dumps({"message": {"content": content}})
        return FakeResponse(body.encode())

    monkeypatch.setattr("sqlguard.agent.planning.urllib.request.urlopen", fake_urlopen)
    return requests


def test_query_sse_replays_run_payload_and_missing_events_by_cursor(web_client, monkeypatch):
    install_ollama(monkeypatch)
    run_id = str(uuid4())
    response = web_client.post(
        "/api/query",
        json={"question": SYNTHETIC_QUESTION, "run_id": run_id},
    )
    assert response.status_code == 200
    assert response.json()["run_id"] == run_id
    stream_response = web_client.get(f"/api/query/stream/{run_id}")
    assert stream_response.status_code == 200
    assert stream_response.headers["content-type"].startswith("text/event-stream")
    streamed = [
        json.loads(line.removeprefix("data: "))
        for line in stream_response.text.splitlines()
        if line.startswith("data: ") and '"event_type"' in line
    ]
    assert [event["event_type"] for event in streamed][0] == "run_started"
    assert streamed[-1]["event_type"] == "run_completed"
    assert [event["run_id"] for event in streamed] == [run_id] * len(streamed)
    assert streamed[0]["data"]["question"] == SYNTHETIC_QUESTION
    assert streamed[0]["module"] == "controller"
    assert any(event.get("data", {}).get("sql") == ALLOWED_SQL for event in streamed)
    assert "data" not in response.json()["events"][0]
    assert "SYNTHETIC-ID-001" not in response.text

    replay_response = web_client.get(
        f"/api/query/stream/{run_id}",
        headers={"Last-Event-ID": "2"},
    )
    assert replay_response.status_code == 200
    replay_ids = [
        int(line.removeprefix("id: "))
        for line in replay_response.text.splitlines()
        if line.startswith("id: ")
    ]
    assert replay_ids and min(replay_ids) > 2
    assert "event: stream_complete" in replay_response.text


def test_live_query_stream_requires_admin_session(web_db):
    client = TestClient(create_app(web_db))
    stream_url = f"/api/query/stream/{uuid4()}"

    assert client.get(stream_url).status_code == 401
    assert (
        client.post(
            "/api/login",
            json={"username": "operator", "password": "123456"},
        ).status_code
        == 200
    )
    assert client.get(stream_url).status_code == 403


def test_synthetic_query_uses_ollama_policy_gate_and_real_sqlite(web_client, monkeypatch):
    requests = install_ollama(monkeypatch)

    response = web_client.post("/api/query", json={"question": SYNTHETIC_QUESTION})

    assert response.status_code == 200
    body = response.json()
    assert body["status"] == "full"
    assert body["execution_status"] == "succeeded"
    assert body["backend"] == "synthetic_sqlite"
    assert body["planner"] == "ollama"
    assert body["model"] == "qwen3:1.7b"
    assert body["gate"]["status"] == "ALLOW"
    assert body["sql"] == ALLOWED_SQL
    assert body["result"]["rows"] == [[101, 120000], [102, 230000]]
    assert body["row_count"] == 2
    assert body["duration_ms"] >= 0
    assert body["run_id"]
    assert_event_contract(body, "run_completed", "succeeded")
    event_types = [event["event_type"] for event in body["events"]]
    assert event_types.index("sql_generation_completed") < event_types.index(
        "security_check_completed"
    )
    assert event_types.index("security_check_completed") < event_types.index("execute_completed")
    assert (
        next(
            event for event in body["events"] if event["event_type"] == "security_check_completed"
        )["status"]
        == "allowed"
    )
    assert (
        next(event for event in body["events"] if event["event_type"] == "execute_completed")[
            "status"
        ]
        == "completed"
    )
    assert "SYNTHETIC-ID-001" not in repr(body["events"])
    assert "SYNTHETIC-REF-001" not in repr(body["events"])
    assert requests[0][1] == 4.0
    prompt = requests[0][0]["messages"][1]["content"]
    assert "Table: orders" in prompt
    assert "identity_number" not in prompt
    persistent_events = SQLiteEventStore.from_env().events_for_run(body["run_id"])
    assert [event.event_type for event in persistent_events] == [
        event["event_type"] for event in body["events"]
    ]
    assert persistent_events[-1].status == "succeeded"


def test_schema_and_query_use_the_same_configured_sqlite_path(web_client, monkeypatch, web_db):
    schema_paths = []
    executor_paths = []
    original_load = SQLiteSchemaAdapter.load_sync

    def load_spy(adapter, role, tables=None):
        schema_paths.append(adapter._uri)
        return original_load(adapter, role, tables)

    class PathRecordingExecutor(SQLiteExecutor):
        def __init__(self, path, policy):
            executor_paths.append(str(path))
            super().__init__(path, policy)

    monkeypatch.setattr(
        "sqlguard.agent.sqlite_schema.SQLiteSchemaAdapter.load_sync",
        load_spy,
    )
    monkeypatch.setattr("sqlguard.agent.runtime.SQLiteExecutor", PathRecordingExecutor)
    install_ollama(monkeypatch)

    response = web_client.post("/api/query", json={"question": SYNTHETIC_QUESTION})

    assert response.json()["status"] == "full"
    assert schema_paths == [f"{web_db.resolve().as_uri()}?mode=ro"]
    assert executor_paths == [str(web_db.resolve())]


@pytest.mark.parametrize(
    "sql",
    [
        "DELETE FROM orders",
        "SELECT order_id FROM orders; SELECT order_id FROM orders",
        "SELECT phone_number FROM customers",
        "SELECT secret FROM private_table",
    ],
)
def test_policy_denials_never_reach_sqlite_executor(web_client, monkeypatch, web_db, sql):
    executed = []

    class RecordingExecutor(SQLiteExecutor):
        async def execute(self, statement, *, role, timeout_seconds, max_rows):
            executed.append(statement)
            return await super().execute(
                statement, role=role, timeout_seconds=timeout_seconds, max_rows=max_rows
            )

    monkeypatch.setattr("sqlguard.agent.runtime.SQLiteExecutor", RecordingExecutor)
    install_ollama(monkeypatch, sql)

    response = web_client.post("/api/query", json={"question": "Question"})
    body = response.json()

    assert response.status_code == 200
    assert body["status"] == "refused"
    assert body["gate"]["status"] == "BLOCK"
    assert body["result"] is None
    assert executed == []
    assert body["execution_status"] == "refused"
    assert str(web_db.resolve()) not in response.text
    assert "Traceback" not in response.text
    assert "sqlite3." not in response.text
    assert "SYNTHETIC-ID-001" not in response.text
    assert "SYNTHETIC-REF-001" not in response.text
    assert_event_contract(body, "run_refused", "refused", "security_rejection")
    gate_event = next(
        event for event in body["events"] if event["event_type"] == "security_check_completed"
    )
    assert gate_event["status"] == "denied"
    assert gate_event["error_category"] == "security_rejection"
    assert not any(
        event["event_type"] == "execute_completed" and event["status"] == "completed"
        for event in body["events"]
    )


@pytest.mark.parametrize(
    ("sql", "violation"),
    [
        ("DELETE FROM orders", "write_operation"),
        (
            "SELECT order_id FROM orders; SELECT order_id FROM orders",
            "multiple_statements",
        ),
        ("SELECT phone_number FROM customers", "column_forbidden"),
        ("SELECT secret FROM private_table", "table_unknown"),
    ],
)
def test_secure_tool_rechecks_policy_when_called_directly(web_db, sql, violation):
    class ExecutorSpy:
        calls = 0

        async def execute(self, sql, *, role, timeout_seconds, max_rows):
            self.calls += 1
            return QueryResult(columns=("result",), rows=(("should not execute",),))

    executor = ExecutorSpy()
    runtime = build_query_runtime(
        SYNTHETIC_ROLE,
        {
            "SQLGUARD_QUERY_SOURCE": "sqlite",
            "SQLGUARD_SQLITE_PATH": str(web_db),
        },
        executor=executor,
        policy=load_policy(SYNTHETIC_POLICY_NAME),
        run_id="direct-secure-tool-test",
    )
    assert runtime is not None

    with pytest.raises(SecurityToolError) as error:
        asyncio.run(runtime.tool.call({"sql": sql}, timeout_seconds=3))

    assert error.value.category == "security_rejection"
    assert runtime.tool.last_decision is not None
    assert not runtime.tool.last_decision.allowed
    assert violation in runtime.tool.last_decision.violations
    assert executor.calls == 0


def test_synthetic_mode_does_not_change_legacy_demo_planner(legacy_db, monkeypatch):
    monkeypatch.setenv("SQLGUARD_WEB_QUERY_MODE", "financial")
    event_path = legacy_db.parent / "events.sqlite3"
    monkeypatch.setenv(EVENT_DB_PATH_ENV, str(event_path))
    client = TestClient(create_app(legacy_db))
    assert (
        client.post("/api/login", json={"username": "admin", "password": "123456"}).status_code
        == 200
    )
    response = client.post(
        "/api/query", json={"question": "Có bao nhiêu khách hàng trong hệ thống?"}
    )

    assert response.status_code == 200
    body = response.json()
    assert body["planner"] == "demo-no-llm"
    assert body["result"]["rows"] == [[2]]
    assert SQLiteEventStore(event_path).events_for_run(body["run_id"])


def test_persistence_failure_does_not_turn_allowed_query_into_success(web_client, monkeypatch):
    from sqlguard.observability.events import EventStoreError

    failing_event_types = set()
    original_emit = SQLiteEventStore.emit

    def failing_emit(store, event):
        if event.event_type == "tool_call_started":
            failing_event_types.add(event.event_type)
            raise EventStoreError("event_store_write_failed")
        original_emit(store, event)

    monkeypatch.setattr(SQLiteEventStore, "emit", failing_emit)
    install_ollama(monkeypatch)

    body = web_client.post("/api/query", json={"question": SYNTHETIC_QUESTION}).json()

    assert failing_event_types == {"tool_call_started"}
    assert body["status"] == "failed"
    assert body["execution_status"] == "failed"
    assert body["gate"]["status"] == "ALLOW"
    assert body["result"] is None
    assert body["events"][-1]["event_type"] == "run_failed"
    assert body["events"][-1]["error_category"] == "event_sink_error"
    assert not any(
        event["event_type"] == "execute_completed" and event["status"] == "completed"
        for event in body["events"]
    )
    persisted_events = SQLiteEventStore.from_env().events_for_run(body["run_id"])
    persisted_types = [event.event_type for event in persisted_events]
    assert "security_check_completed" in persisted_types
    assert persisted_types[-1] == "run_failed"
    assert persisted_events[-1].error_category == "event_sink_error"
    assert "tool_call_started" not in persisted_types


def test_ollama_failure_is_reported_without_demo_fallback(web_client, monkeypatch):
    calls = install_ollama(
        monkeypatch,
        failure=urllib.error.URLError("private endpoint detail"),
    )

    response = web_client.post("/api/query", json={"question": SYNTHETIC_QUESTION})

    assert response.status_code == 200
    body = response.json()
    assert body["status"] == "failed"
    assert body["execution_status"] == "failed"
    assert body["planner"] == "ollama"
    assert body["sql"] is None
    assert body["result"] is None
    assert "Ollama" in body["reason"]
    assert "private" not in response.text
    assert len(calls) == 1
    assert_event_contract(body, "run_failed", "failed", "planner_error")
    event_types = [event["event_type"] for event in body["events"]]
    assert (
        next(
            event for event in body["events"] if event["event_type"] == "sql_generation_completed"
        )["status"]
        == "failed"
    )
    assert "security_check_completed" not in event_types
    assert "execute_completed" not in event_types


def test_invalid_ollama_output_is_reported_without_fallback(web_client, monkeypatch):
    monkeypatch.setattr(
        "sqlguard.agent.planning.urllib.request.urlopen",
        lambda *args, **kwargs: FakeResponse(b'{"message":{"content":"not-json"}}'),
    )

    body = web_client.post("/api/query", json={"question": SYNTHETIC_QUESTION}).json()

    assert body["status"] == "failed"
    assert body["planner"] == "ollama"
    assert body["sql"] is None
    assert body["result"] is None


@pytest.mark.parametrize(
    ("error_category", "expected_reason"),
    [
        ("db_unavailable", "Không thể truy cập database demo"),
        ("db_timeout", "Truy vấn vượt quá thời gian cho phép"),
    ],
)
def test_query_executor_failure_has_safe_error_and_no_result(
    web_client, monkeypatch, error_category, expected_reason
):
    class FailingExecutor(SQLiteExecutor):
        async def execute(self, sql, *, role, timeout_seconds, max_rows):
            raise ExecutorError(error_category)

    monkeypatch.setattr("sqlguard.agent.runtime.SQLiteExecutor", FailingExecutor)
    install_ollama(monkeypatch)

    body = web_client.post("/api/query", json={"question": SYNTHETIC_QUESTION}).json()

    assert body["status"] == "failed"
    assert body["execution_status"] == "failed"
    assert body["gate"]["status"] == "ALLOW"
    assert body["result"] is None
    assert expected_reason in body["reason"]
    assert_event_contract(body, "run_failed", "failed", error_category)
    tool_event = next(
        event for event in body["events"] if event["event_type"] == "execute_completed"
    )
    assert tool_event["status"] == "failed"
    assert tool_event["error_category"] == error_category
    assert not any(
        event["event_type"] == "execute_completed" and event["status"] == "completed"
        for event in body["events"]
    )


def test_synthetic_database_configuration_fails_clearly_and_does_not_fallback(
    web_client, monkeypatch, web_db
):
    monkeypatch.setenv("SQLGUARD_WEB_DEMO_SQLITE_PATH", str(web_db.parent / "missing.sqlite"))
    monkeypatch.setenv("SQLGUARD_FINANCIAL_DB", str(web_db))
    calls = install_ollama(monkeypatch)

    response = web_client.post("/api/query", json={"question": SYNTHETIC_QUESTION})

    assert response.status_code == 503
    assert "Không tìm thấy database SQLite tổng hợp" in response.json()["detail"]
    assert str(web_db) not in response.text
    assert calls == []


def test_synthetic_mode_requires_explicit_database_path(web_client, monkeypatch):
    monkeypatch.delenv("SQLGUARD_WEB_DEMO_SQLITE_PATH")
    response = web_client.post("/api/query", json={"question": SYNTHETIC_QUESTION})

    assert response.status_code == 503
    assert "Chưa cấu hình database SQLite tổng hợp" in response.json()["detail"]


def test_invalid_synthetic_database_is_not_replaced_by_financial_db(
    web_client, monkeypatch, web_db, tmp_path
):
    invalid_db = tmp_path / "invalid.sqlite"
    invalid_db.write_text("not a SQLite database", encoding="utf-8")
    monkeypatch.setenv("SQLGUARD_WEB_DEMO_SQLITE_PATH", str(invalid_db))
    monkeypatch.setenv("SQLGUARD_FINANCIAL_DB", str(web_db))
    calls = install_ollama(monkeypatch)

    response = web_client.post("/api/query", json={"question": SYNTHETIC_QUESTION})

    assert response.status_code == 503
    assert response.json()["detail"] == "Không thể đọc schema SQLite đã cấu hình."
    assert str(invalid_db) not in response.text
    assert calls == []


def test_synthetic_query_endpoint_still_requires_login(web_db, monkeypatch):
    monkeypatch.setenv("SQLGUARD_WEB_QUERY_MODE", "synthetic_sqlite")
    monkeypatch.setenv("SQLGUARD_WEB_DEMO_SQLITE_PATH", str(web_db))
    response = TestClient(create_app(web_db)).post(
        "/api/query", json={"question": SYNTHETIC_QUESTION}
    )

    assert response.status_code == 401
