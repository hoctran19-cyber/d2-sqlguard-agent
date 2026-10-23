from datetime import UTC, datetime, timedelta
from uuid import UUID

import pytest

pytest.importorskip("fastapi")
pytest.importorskip("httpx")

from fastapi.testclient import TestClient  # noqa: E402

from sqlguard.observability.events import (  # noqa: E402
    EVENT_DB_PATH_ENV,
    Event,
    EventStoreError,
    SQLiteEventStore,
)
from sqlguard.web.app import create_app  # noqa: E402


@pytest.fixture
def history_client(tmp_path, monkeypatch):
    monkeypatch.setenv(EVENT_DB_PATH_ENV, str(tmp_path / "events.sqlite3"))
    client = TestClient(create_app(tmp_path / "financial.sqlite"))
    return client


def login(client, username):
    return client.post("/api/login", json={"username": username, "password": "123456"})


def make_event(run_id, event_type, timestamp, *, status=None, duration_ms=None, category=None):
    return Event(
        run_id=run_id,
        event_type=event_type,
        timestamp=timestamp,
        status=status,
        duration_ms=duration_ms,
        error_category=category,
    )


def seed_run(store, run_id, started, *, status="succeeded", category=None):
    store.emit(make_event(run_id, "run_started", started))
    store.emit(make_event(run_id, "security_check_completed", started + timedelta(seconds=1)))
    terminal_event = {
        "succeeded": "run_completed",
        "refused": "run_refused",
        "failed": "run_failed",
    }[status]
    store.emit(
        make_event(
            run_id,
            terminal_event,
            started + timedelta(seconds=2),
            status=status,
            duration_ms=2000,
            category=category,
        )
    )


def test_history_lists_unique_runs_newest_first_and_paginates(history_client, monkeypatch):
    login(history_client, "admin")
    store = SQLiteEventStore.from_env()
    base = datetime(2026, 10, 23, 12, 0, tzinfo=UTC)
    run_ids = [str(UUID(int=index)) for index in (1, 2, 3)]
    for index, run_id in enumerate(run_ids):
        seed_run(store, run_id, base + timedelta(minutes=index))

    first = history_client.get("/api/query/history?limit=2&offset=0")
    second = history_client.get("/api/query/history?limit=2&offset=2")

    assert first.status_code == second.status_code == 200
    first_body, second_body = first.json(), second.json()
    assert first_body["total"] == 3
    assert first_body["limit"] == 2 and first_body["offset"] == 0
    assert [item["run_id"] for item in first_body["items"]] == run_ids[::-1][:2]
    assert [item["run_id"] for item in second_body["items"]] == run_ids[:1]
    assert set(item["run_id"] for item in first_body["items"]).isdisjoint(
        item["run_id"] for item in second_body["items"]
    )

    newest = first_body["items"][0]
    assert newest["started_at"] == (base + timedelta(minutes=2)).isoformat()
    assert newest["ended_at"] == (base + timedelta(minutes=2, seconds=2)).isoformat()
    assert newest["event_count"] == 3
    assert newest["status"] == "succeeded"
    assert newest["duration_ms"] == 2000
    assert newest["error_category"] is None


def test_history_order_is_chronological_for_timestamps_with_mixed_precision(history_client):
    login(history_client, "admin")
    store = SQLiteEventStore.from_env()
    early = str(UUID(int=10))
    late = str(UUID(int=11))
    store.emit(
        make_event(
            early,
            "run_started",
            datetime(2026, 10, 23, 12, 0, 0, 100000, tzinfo=UTC),
        )
    )
    store.emit(make_event(late, "run_started", datetime(2026, 10, 23, 12, 0, 0, tzinfo=UTC)))

    body = history_client.get("/api/query/history").json()

    assert [run["run_id"] for run in body["items"]] == [early, late]


def test_history_does_not_infer_status_without_terminal_event(history_client):
    login(history_client, "admin")
    run_id = str(UUID(int=21))
    started = datetime(2026, 10, 23, 12, 0, tzinfo=UTC)
    SQLiteEventStore.from_env().emit(make_event(run_id, "run_started", started))

    body = history_client.get("/api/query/history").json()

    assert body["items"] == [
        {
            "run_id": run_id,
            "started_at": started.isoformat(),
            "ended_at": None,
            "event_count": 1,
            "status": None,
            "duration_ms": None,
            "error_category": None,
        }
    ]


def test_history_detail_preserves_event_order_and_returns_not_found_safely(history_client):
    login(history_client, "admin")
    run_id = str(UUID(int=42))
    started = datetime(2026, 10, 23, 12, 0, tzinfo=UTC)
    seed_run(
        SQLiteEventStore.from_env(),
        run_id,
        started,
        status="refused",
        category="security_rejection",
    )

    response = history_client.get(f"/api/query/history/{run_id}")

    assert response.status_code == 200
    body = response.json()
    assert body["run_id"] == run_id
    assert [event["event_type"] for event in body["events"]] == [
        "run_started",
        "security_check_completed",
        "run_refused",
    ]
    assert body["events"][-1]["status"] == "refused"
    assert body["events"][-1]["error_category"] == "security_rejection"
    assert set(body["events"][-1]) == {
        "run_id",
        "event_type",
        "timestamp",
        "status",
        "duration_ms",
        "error_category",
    }
    assert not {"question", "sql", "result"} & body.keys()
    assert history_client.get(f"/api/query/history/{UUID(int=43)}").status_code == 404
    assert history_client.get("/api/query/history/not-a-run-id").status_code == 404


@pytest.mark.parametrize(
    "params",
    [
        "limit=0",
        "limit=101",
        "limit=-1",
        "offset=-1",
        "offset=1000001",
    ],
)
def test_history_rejects_invalid_pagination(history_client, params):
    login(history_client, "admin")

    assert history_client.get(f"/api/query/history?{params}").status_code == 422


def test_history_requires_admin_and_allows_admin_only(history_client):
    assert history_client.get("/api/query/history").status_code == 401
    assert history_client.get(f"/api/query/history/{UUID(int=1)}").status_code == 401

    for username in ("operator", "analyst", "credit"):
        login(history_client, username)
        assert history_client.get("/api/query/history").status_code == 403
        assert history_client.get(f"/api/query/history/{UUID(int=1)}").status_code == 403
        history_client.post("/api/logout", json={})

    login(history_client, "eval")
    assert history_client.get("/api/query/history").status_code == 403
    assert history_client.get(f"/api/query/history/{UUID(int=1)}").status_code == 403
    history_client.post("/api/logout", json={})

    login(history_client, "admin")
    assert history_client.get("/api/query/history").status_code == 200


@pytest.mark.parametrize("path", ["/api/query/history", f"/api/query/history/{UUID(int=1)}"])
def test_history_store_errors_are_safe(history_client, monkeypatch, tmp_path, path):
    login(history_client, "admin")

    def fail(*args, **kwargs):
        raise EventStoreError("event_store_read_failed")

    monkeypatch.setattr(SQLiteEventStore, "list_runs", fail)
    monkeypatch.setattr(SQLiteEventStore, "events_for_run", fail)

    response = history_client.get(path)

    assert response.status_code == 503
    assert response.json() == {"detail": "Không thể đọc lịch sử Query."}
    assert str(tmp_path) not in response.text
    assert "Traceback" not in response.text
    assert "sqlite3" not in response.text


def test_history_returns_empty_data_without_exposing_unstored_query_payloads(history_client):
    login(history_client, "admin")

    listing = history_client.get("/api/query/history")

    assert listing.status_code == 200
    assert listing.json() == {"items": [], "total": 0, "limit": 20, "offset": 0}
    assert "question" not in listing.text
    assert "sql" not in listing.text
    assert "result" not in listing.text
