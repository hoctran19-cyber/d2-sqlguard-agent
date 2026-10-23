import io
import json
import sqlite3
import urllib.error

import pytest

pytest.importorskip("fastapi")
pytest.importorskip("httpx")

from fastapi.testclient import TestClient  # noqa: E402

from sqlguard.agent.sqlite_schema import SQLiteSchemaAdapter  # noqa: E402
from sqlguard.demo_fixture import create_demo_database  # noqa: E402
from sqlguard.security.service import ExecutorError  # noqa: E402
from sqlguard.security.sqlite import SQLiteExecutor  # noqa: E402
from sqlguard.web.app import create_app  # noqa: E402
from sqlguard.web.query_service import SYNTHETIC_QUESTION  # noqa: E402

ALLOWED_SQL = "SELECT order_id, total_amount_vnd FROM orders ORDER BY order_id"


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
    assert requests[0][1] == 4.0
    prompt = requests[0][0]["messages"][1]["content"]
    assert "Table: orders" in prompt
    assert "identity_number" not in prompt


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
def test_policy_denials_never_reach_sqlite_executor(web_client, monkeypatch, sql):
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


def test_synthetic_mode_does_not_change_legacy_demo_planner(legacy_db, monkeypatch):
    monkeypatch.setenv("SQLGUARD_WEB_QUERY_MODE", "financial")
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


def test_query_executor_failure_has_safe_error_and_no_result(web_client, monkeypatch):
    class FailingExecutor(SQLiteExecutor):
        async def execute(self, sql, *, role, timeout_seconds, max_rows):
            raise ExecutorError("db_unavailable")

    monkeypatch.setattr("sqlguard.agent.runtime.SQLiteExecutor", FailingExecutor)
    install_ollama(monkeypatch)

    body = web_client.post("/api/query", json={"question": SYNTHETIC_QUESTION}).json()

    assert body["status"] == "failed"
    assert body["execution_status"] == "failed"
    assert body["gate"]["status"] == "ALLOW"
    assert body["result"] is None
    assert "Không thể truy cập database demo" in body["reason"]


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
