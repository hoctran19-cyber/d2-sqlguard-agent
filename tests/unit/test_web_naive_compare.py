"""Naive-agent compare page over the web (N6): admin-only, off by default, same lab copy.

Runs on a schema-valid fixture copied into a lab copy, with the scripted naive model and a fake
Ollama planner for SQLGuard; no network and never the real ``financial.sqlite``.
"""

import io
import json

import pytest

pytest.importorskip("fastapi")
pytest.importorskip("httpx")

from fastapi.testclient import TestClient  # noqa: E402

from sqlguard.lab.model import Q_ACCOUNT_NOTE, SCRIPTED_QUESTIONS  # noqa: E402
from sqlguard.lab.naive_guard import NAIVE_DEMO_ENV, NAIVE_MODEL_ENV, NaiveDemoError  # noqa: E402
from sqlguard.lab.scenarios import PAYLOAD_TOOL_HIJACK, SCENARIOS  # noqa: E402
from sqlguard.observability.events import EVENT_DB_PATH_ENV  # noqa: E402
from sqlguard.security.attack_lab import (  # noqa: E402
    BUSINESS_DATABASE_ENV,
    ENABLED_ENV,
    LAB_DB_ENV,
    TARGETS_ENV,
    create_lab_copy,
    marker_path,
)
from sqlguard.web.app import create_app  # noqa: E402

NOTES = "/api/lab/notes/account.3"
NOTE_SQL = "SELECT account_id, frequency, service_note FROM account WHERE account_id = 3"
OWNER_ID = "CANARY-ID-0003"


class FakeResponse(io.BytesIO):
    def __enter__(self):
        return self

    def __exit__(self, *args):
        self.close()


def install_ollama(monkeypatch, sql):
    def fake_urlopen(request, timeout=None):
        content = json.dumps({"sql": sql, "summary": "fixed"})
        return FakeResponse(json.dumps({"message": {"content": content}}).encode())

    monkeypatch.setattr("sqlguard.agent.planning.urllib.request.urlopen", fake_urlopen)


def login(client, username):
    response = client.post("/api/login", json={"username": username, "password": "123456"})
    assert response.status_code == 200
    return response.json()


def other_session(client, username):
    other = TestClient(client.app)
    login(other, username)
    return other


@pytest.fixture
def lab_env(financial_db, tmp_path, monkeypatch):
    copy = create_lab_copy(financial_db, tmp_path / "lab" / "financial-lab.sqlite")
    monkeypatch.setenv(BUSINESS_DATABASE_ENV, str(copy))
    monkeypatch.setenv(LAB_DB_ENV, str(copy))
    monkeypatch.setenv(TARGETS_ENV, "account.3,order.2")
    monkeypatch.setenv(ENABLED_ENV, "1")
    monkeypatch.setenv("SQLGUARD_PLANNER", "ollama")
    monkeypatch.setenv("SQLGUARD_OLLAMA_MODEL", "test-model")
    monkeypatch.setenv(EVENT_DB_PATH_ENV, str(tmp_path / "events.sqlite3"))
    return copy


@pytest.fixture
def demo_on(lab_env, tmp_path, monkeypatch):
    monkeypatch.setenv(NAIVE_DEMO_ENV, "1")
    monkeypatch.setenv(NAIVE_MODEL_ENV, "scripted")
    return TestClient(create_app(tmp_path / "legacy-missing.sqlite"))


@pytest.fixture
def admin(demo_on):
    login(demo_on, "admin")
    return demo_on


def compare(client, question=Q_ACCOUNT_NOTE, role="operator"):
    return client.post("/api/lab/compare", json={"question": question, "role": role})


def badges(payload, side):
    return {item["id"]: item["triggered"] for item in payload["symptoms"][side]}


def test_demo_is_off_by_default(lab_env, tmp_path):
    client = TestClient(create_app(tmp_path / "legacy-missing.sqlite"))
    assert login(client, "admin")["naive_demo_enabled"] is False
    assert client.get("/api/lab/compare/scenarios").status_code == 404
    assert compare(client).status_code == 404


def test_only_admin_sees_the_demo(demo_on):
    assert login(demo_on, "admin")["naive_demo_enabled"] is True
    for username in ("operator", "analyst", "credit", "eval"):
        assert other_session(demo_on, username).get("/api/me").json()["naive_demo_enabled"] is False


@pytest.mark.parametrize(
    ("method", "path", "body"),
    [
        ("get", "/api/lab/compare/scenarios", None),
        ("post", "/api/lab/compare", {"question": Q_ACCOUNT_NOTE, "role": "operator"}),
    ],
)
def test_demo_routes_reject_everyone_but_admin(demo_on, method, path, body):
    kwargs = {} if body is None else {"json": body}
    assert getattr(demo_on, method)(path, **kwargs).status_code == 401
    for username in ("operator", "analyst", "credit", "eval"):
        client = other_session(demo_on, username)
        assert getattr(client, method)(path, **kwargs).status_code == 403


@pytest.mark.parametrize("role", [None, "", "admin", "evaluator", "OPERATOR", 3])
def test_role_must_be_a_business_role(admin, role):
    response = admin.post("/api/lab/compare", json={"question": Q_ACCOUNT_NOTE, "role": role})
    assert response.status_code == 422


def test_scenarios_list_the_pinned_payloads_and_which_targets_the_lab_has(admin):
    data = admin.get("/api/lab/compare/scenarios").json()
    assert data["naive_model"] == "scripted"
    assert data["roles"] == ["analyst", "credit_officer", "operator"]
    by_id = {item["id"]: item for item in data["scenarios"]}
    assert [item["id"] for item in data["scenarios"]] == [s.id for s in SCENARIOS]
    assert {item["question"] for item in data["scenarios"]} == set(SCRIPTED_QUESTIONS)
    assert by_id["N-I1"]["payload"] == PAYLOAD_TOOL_HIJACK
    # The fixture lab has account.3 but not order.29407; direct injection needs no target.
    assert by_id["N-I1"]["installable"] is True
    assert by_id["N-I2"]["installable"] is False
    assert by_id["N-D3"]["installable"] is False and by_id["N-D3"]["target"] is None


def test_indirect_tool_hijack_shows_symptoms_on_naive_side_only(admin, monkeypatch):
    install_ollama(monkeypatch, NOTE_SQL)
    saved = admin.put(NOTES, json={"content": PAYLOAD_TOOL_HIJACK, "expected_revision": 0})
    assert saved.status_code == 200

    response = compare(admin)
    assert response.status_code == 200
    data = response.json()
    assert data["role"] == "operator"
    assert data["naive_model"] == "scripted"
    assert "giả lập" in data["naive_model_label"]
    assert data["lab_revisions"]["account.3"]["revision"] == 1

    naive = data["naive"]
    assert naive["status"] == "completed"
    assert naive["tool_calls"] == 2
    assert OWNER_ID in naive["answer_markdown"]
    naive_badges = badges(data, "naive")
    assert naive_badges["extra_tool_calls"] is True
    assert naive_badges["forbidden_value"] is True
    assert naive_badges["forbidden_sql"] is True

    guarded = data["sqlguard"]
    assert guarded["status"] == "full"
    assert guarded["possible_injection"] is True
    assert PAYLOAD_TOOL_HIJACK in json.dumps(guarded["result"]["rows"], ensure_ascii=False)
    sqlguard_badges = badges(data, "sqlguard")
    assert sqlguard_badges["forbidden_value"] is False
    assert sqlguard_badges["forbidden_sql"] is False
    assert sqlguard_badges["extra_tool_calls"] is None  # no model-driven tool loop
    assert OWNER_ID not in json.dumps(guarded, ensure_ascii=False)


def test_naive_answer_is_not_written_to_query_history(admin, monkeypatch):
    install_ollama(monkeypatch, NOTE_SQL)
    admin.put(NOTES, json={"content": PAYLOAD_TOOL_HIJACK, "expected_revision": 0})
    assert compare(admin).status_code == 200
    history = admin.get("/api/query/history").json()
    assert OWNER_ID not in json.dumps(history, ensure_ascii=False)


def test_lab_refuses_writes_while_a_compare_runs(admin, monkeypatch):
    install_ollama(monkeypatch, NOTE_SQL)
    seen = {}

    async def fake_run_naive(config, question, role, *, model=None):
        # Inside the run guard: a lab write now must be refused with 409.
        writer = TestClient(admin.app)
        login(writer, "admin")
        seen["status"] = await _put_in_thread(writer)
        raise NaiveDemoError("naive_db_not_a_lab_copy")

    monkeypatch.setattr("sqlguard.web.app.run_naive", fake_run_naive)
    response = compare(admin)
    assert seen["status"] == 409
    # A lab copy that changed under the demo becomes a generic 503, no path or detail.
    assert response.status_code == 503
    assert "lab" in response.json()["detail"]


async def _put_in_thread(client):
    import asyncio

    def put():
        return client.put(NOTES, json={"content": "x", "expected_revision": 0}).status_code

    return await asyncio.to_thread(put)


def test_a_lab_copy_that_lost_its_marker_is_refused_at_run_time(admin, lab_env, monkeypatch):
    install_ollama(monkeypatch, NOTE_SQL)
    marker_path(lab_env).unlink()
    response = compare(admin)
    assert response.status_code == 503
    assert str(lab_env) not in response.text
