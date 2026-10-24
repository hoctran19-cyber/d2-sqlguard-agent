"""Web access for operator / analyst / credit_officer through business_financial_v1.

Business roles query only when SQLGUARD_BUSINESS_FINANCIAL_DB points at a database that passes the
schema preflight (otherwise test_web_roles.py keeps every data API at 403). The role always comes
from the session; Ollama is faked, and the legacy financial database is never touched.
"""

import io
import json
from uuid import uuid4

import pytest

pytest.importorskip("fastapi")
pytest.importorskip("httpx")

from fastapi.testclient import TestClient  # noqa: E402
from tests.conftest import create_financial_db  # noqa: E402

from sqlguard.observability.events import EVENT_DB_PATH_ENV  # noqa: E402
from sqlguard.security.business_database import BUSINESS_DATABASE_ENV  # noqa: E402
from sqlguard.web.app import create_app  # noqa: E402
from sqlguard.web.database import FinancialDatabase  # noqa: E402

USERS = {"operator": "operator", "analyst": "analyst", "credit": "credit_officer"}


class FakeResponse(io.BytesIO):
    def __enter__(self):
        return self

    def __exit__(self, *args):
        self.close()


def install_ollama(monkeypatch, sql):
    calls = []

    def fake_urlopen(request, timeout=None):
        calls.append(json.loads(request.data))
        content = json.dumps({"sql": sql, "summary": "fixed"})
        return FakeResponse(json.dumps({"message": {"content": content}}).encode())

    monkeypatch.setattr("sqlguard.agent.planning.urllib.request.urlopen", fake_urlopen)
    return calls


@pytest.fixture
def app_client(financial_db, tmp_path, monkeypatch):
    monkeypatch.setenv(BUSINESS_DATABASE_ENV, str(financial_db))
    monkeypatch.setenv("SQLGUARD_PLANNER", "ollama")
    monkeypatch.setenv("SQLGUARD_OLLAMA_MODEL", "test-model")
    monkeypatch.setenv("SQLGUARD_OLLAMA_TIMEOUT_SECONDS", "4")
    monkeypatch.setenv(EVENT_DB_PATH_ENV, str(tmp_path / "events.sqlite3"))

    def legacy_database_call(*args, **kwargs):
        raise AssertionError("Business users must not reach the legacy database")

    monkeypatch.setattr(FinancialDatabase, "table_names", legacy_database_call)
    monkeypatch.setattr(FinancialDatabase, "run_page", legacy_database_call)
    return TestClient(create_app(tmp_path / "legacy-missing.sqlite"))


def login(client, username):
    response = client.post("/api/login", json={"username": username, "password": "123456"})
    assert response.status_code == 200
    return response.json()


def sql(client, text, **extra):
    return client.post("/api/sql", json={"sql": text, **extra})


@pytest.mark.parametrize("username", USERS)
def test_business_user_gets_data_access_and_its_own_tables(app_client, username):
    assert login(app_client, username)["data_access"] is True
    body = app_client.get("/api/tables").json()
    assert body["policy"] == "business-financial-v1"
    expected = {
        "operator": {"account", "card", "client", "disp", "district", "order", "trans"},
        "analyst": {"account", "client", "disp", "district", "trans"},
        "credit_officer": {"account", "client", "disp", "district", "loan", "order", "trans"},
    }[USERS[username]]
    assert set(body["tables"]) == expected
    # Every default query of the Database page is accepted for this role.
    for table, default_sql in body["default_sql"].items():
        response = sql(app_client, default_sql)
        assert response.status_code == 200, (table, response.json())
        assert "CANARY" not in json.dumps(response.json())


def test_info_reports_the_enforced_policy(app_client):
    login(app_client, "analyst")
    info = app_client.get("/api/info").json()
    assert info["access"] == "policy"
    assert info["effective_access"]["data_queries"] == "enabled"
    assert info["effective_access"]["policy_version"] == "business-financial-v1"
    assert info["reference"]["aggregate_only"] is True


def test_manual_sql_is_gated_per_role(app_client):
    login(app_client, "operator")
    partial = sql(app_client, "SELECT client_id, full_name, id_number FROM client")
    assert partial.status_code == 200
    assert partial.json()["columns"] == ["client_id", "full_name"]
    assert partial.json()["removed_columns"] == ["client.id_number"]
    assert "CANARY" not in partial.text
    denied = sql(app_client, "SELECT amount FROM loan")
    assert denied.status_code == 422 and "bảng ngoài policy" in denied.json()["detail"]
    assert sql(app_client, "DELETE FROM client").status_code == 422
    assert sql(app_client, "SELECT name FROM sqlite_master").status_code == 422

    login(app_client, "analyst")
    row_level = sql(app_client, "SELECT client_id, gender FROM client")
    assert row_level.status_code == 422 and "khóa cá thể" in row_level.json()["detail"]
    grouped = sql(app_client, "SELECT gender, COUNT(*) FROM client GROUP BY gender")
    assert grouped.status_code == 200


def test_role_in_body_or_headers_cannot_escalate(app_client):
    login(app_client, "credit")
    spoof = {"X-Role": "admin", "X-User-Role": "operator"}
    response = sql(app_client, "SELECT address FROM client", role="operator")
    assert response.status_code == 422
    response = app_client.post(
        "/api/sql", json={"sql": "SELECT address FROM client", "role": "admin"}, headers=spoof
    )
    assert response.status_code == 422
    assert app_client.get("/api/me").json()["role"] == "credit_officer"


def test_query_runs_the_agent_with_the_session_role(app_client, monkeypatch):
    calls = install_ollama(monkeypatch, "SELECT loan_id, amount, status FROM loan")
    login(app_client, "credit")
    body = app_client.post("/api/query", json={"question": "Khoản vay theo trạng thái"}).json()
    assert (body["backend"], body["role"], body["status"]) == (
        "business_sqlite",
        "credit_officer",
        "full",
    )
    assert body["result"]["columns"] == ["loan_id", "amount", "status"]
    assert body["policy_version"] == "business-financial-v1"
    system_prompt = calls[0]["messages"][0]["content"]
    assert 'role is "credit_officer"' in system_prompt and "SQLite" in system_prompt


def test_query_returns_a_partial_answer_without_forbidden_columns(app_client, monkeypatch):
    install_ollama(monkeypatch, "SELECT client_id, full_name, id_number FROM client")
    login(app_client, "operator")
    body = app_client.post("/api/query", json={"question": "Số định danh khách hàng"}).json()
    assert body["status"] == "partial"
    assert body["omitted_fields"] == ["client.id_number"]
    assert body["result"]["columns"] == ["client_id", "full_name"]
    assert "CANARY" not in json.dumps(body)


def test_query_refuses_row_level_answers_for_the_analyst(app_client, monkeypatch):
    install_ollama(monkeypatch, "SELECT account_id, amount FROM trans")
    login(app_client, "analyst")
    body = app_client.post("/api/query", json={"question": "Liệt kê giao dịch"}).json()
    assert body["status"] == "refused"
    assert body["gate"]["status"] == "BLOCK"
    assert body["result"] is None


def test_business_query_lets_the_model_repair_a_denied_query(app_client, monkeypatch):
    answers = iter(
        [
            "SELECT strftime('%Y', trans.date) AS y, COUNT(*) FROM account GROUP BY y",
            "SELECT frequency, COUNT(DISTINCT account_id) FROM account GROUP BY frequency",
        ]
    )
    calls = []

    def fake_urlopen(request, timeout=None):
        calls.append(request)
        content = json.dumps({"sql": next(answers), "summary": "fixed"})
        return FakeResponse(json.dumps({"message": {"content": content}}).encode())

    monkeypatch.setattr("sqlguard.agent.planning.urllib.request.urlopen", fake_urlopen)
    login(app_client, "analyst")
    body = app_client.post("/api/query", json={"question": "Tài khoản theo tần suất"}).json()
    assert body["status"] == "full" and len(calls) == 2
    assert body["sql"].startswith("SELECT frequency")


def test_another_user_cannot_read_a_run_stream(app_client, monkeypatch, financial_db, tmp_path):
    install_ollama(monkeypatch, "SELECT gender, COUNT(*) FROM client GROUP BY gender")
    login(app_client, "analyst")
    run_id = str(uuid4())
    response = app_client.post("/api/query", json={"question": "Theo giới tính", "run_id": run_id})
    assert response.status_code == 200
    other = TestClient(app_client.app)
    login(other, "operator")
    assert other.get(f"/api/query/stream/{run_id}").status_code == 404
    assert other.post("/api/query", json={"question": "x", "run_id": run_id}).status_code == 404


def test_schema_drift_switches_business_access_off(app_client, tmp_path, monkeypatch):
    drifted = create_financial_db(tmp_path / "drift.sqlite", drop_column="address")
    monkeypatch.setenv(BUSINESS_DATABASE_ENV, str(drifted))
    assert login(app_client, "operator")["data_access"] is False
    assert app_client.get("/api/tables").status_code == 403
    assert sql(app_client, "SELECT client_id FROM client").status_code == 403
    assert app_client.get("/api/info").json()["access"] == "reference"


def test_history_stays_admin_only(app_client):
    login(app_client, "operator")
    assert app_client.get("/api/query/history").status_code == 403
