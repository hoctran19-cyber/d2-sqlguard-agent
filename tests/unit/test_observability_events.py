import sqlite3
from datetime import UTC, datetime, timedelta, timezone

import pytest

from sqlguard.observability.events import (
    EVENT_DB_PATH_ENV,
    CompositeEventSink,
    Event,
    EventStoreError,
    InMemoryEventSink,
    SQLiteEventStore,
    default_event_db_path,
)


def make_event(run_id, event_type, *, timestamp=None, status=None, duration_ms=None, category=None):
    return Event(
        run_id=run_id,
        event_type=event_type,
        timestamp=timestamp or datetime(2026, 10, 23, 12, 0, tzinfo=UTC),
        status=status,
        duration_ms=duration_ms,
        error_category=category,
    )


def test_sqlite_event_store_round_trips_all_fields_in_utc(tmp_path):
    store = SQLiteEventStore(tmp_path / "state" / "events.sqlite3")
    original_timestamp = datetime(2026, 10, 23, 19, 30, tzinfo=timezone(timedelta(hours=7)))
    event = make_event(
        "run-roundtrip",
        "execute_completed",
        timestamp=original_timestamp,
        status="failed",
        duration_ms=12.5,
        category="db_timeout",
    )

    store.emit(event)
    [restored] = store.events_for_run("run-roundtrip")

    assert restored.run_id == event.run_id
    assert restored.event_type == event.event_type
    assert restored.timestamp == original_timestamp.astimezone(UTC)
    assert restored.timestamp.tzinfo == UTC
    assert restored.status == event.status
    assert restored.duration_ms == event.duration_ms
    assert restored.error_category == event.error_category
    assert store.path.parent.is_dir()


def test_sqlite_event_store_persists_across_instances_and_isolates_runs(tmp_path):
    path = tmp_path / "events.sqlite3"
    first_store = SQLiteEventStore(path)
    first_store.emit(make_event("run-a", "run_started"))
    first_store.emit(make_event("run-b", "run_started"))
    first_store.emit(make_event("run-a", "run_completed", status="succeeded"))

    reopened_store = SQLiteEventStore(path)

    assert [event.event_type for event in reopened_store.events_for_run("run-a")] == [
        "run_started",
        "run_completed",
    ]
    assert [event.event_type for event in reopened_store.events_for_run("run-b")] == ["run_started"]


def test_sqlite_event_store_preserves_nullable_fields_and_repeated_writes(tmp_path):
    store = SQLiteEventStore(tmp_path / "events.sqlite3")
    event = make_event("run-nullable", "run_started")

    store.emit(event)
    store.emit(event)

    restored = store.events_for_run("run-nullable")
    assert len(restored) == 2
    assert restored == [event, event]
    assert restored[0].status is None
    assert restored[0].duration_ms is None
    assert restored[0].error_category is None


def test_sqlite_event_store_uses_configured_or_external_default_path(tmp_path, monkeypatch):
    configured = tmp_path / "configured" / "events.sqlite3"
    store = SQLiteEventStore.from_env({EVENT_DB_PATH_ENV: str(configured)})

    assert store.path == configured
    assert configured.is_file()
    monkeypatch.setenv("XDG_STATE_HOME", str(tmp_path / "state"))
    default_path = default_event_db_path()
    assert default_path == tmp_path / "state" / "sqlguard" / "events.sqlite3"
    assert SQLiteEventStore.from_env({}).path == default_path


@pytest.mark.parametrize(
    "configured",
    ["", ":memory:"],
)
def test_sqlite_event_store_rejects_nonpersistent_paths_safely(configured):
    with pytest.raises(EventStoreError) as error:
        SQLiteEventStore(configured)

    assert error.value.category == "event_store_config_error"
    if configured:
        assert configured not in str(error.value)


def test_sqlite_event_store_maps_initialization_and_write_errors_safely(tmp_path):
    not_a_directory = tmp_path / "file"
    not_a_directory.write_text("not a directory", encoding="utf-8")
    with pytest.raises(EventStoreError) as init_error:
        SQLiteEventStore(not_a_directory / "events.sqlite3")
    assert init_error.value.category == "event_store_unavailable"
    assert str(tmp_path) not in str(init_error.value)

    db_path = tmp_path / "events.sqlite3"
    store = SQLiteEventStore(db_path)
    db_path.unlink()
    db_path.mkdir()
    with pytest.raises(EventStoreError) as write_error:
        store.emit(make_event("run-write-failure", "run_started"))
    assert write_error.value.category == "event_store_write_failed"
    assert str(tmp_path) not in str(write_error.value)


def test_sqlite_event_store_rejects_untrusted_error_text_without_persisting_it(tmp_path):
    path = tmp_path / "events.sqlite3"
    store = SQLiteEventStore(path)

    with pytest.raises(EventStoreError) as error:
        store.emit(
            make_event(
                "run-secret",
                "run_failed",
                status="failed",
                category="password=private-token",
            )
        )

    assert error.value.category == "event_store_invalid_event"
    with sqlite3.connect(path) as connection:
        [(row_count,)] = connection.execute("SELECT COUNT(*) FROM observability_events").fetchall()
        columns = {row[1] for row in connection.execute("PRAGMA table_info(observability_events)")}
    assert row_count == 0
    assert columns == {
        "sequence",
        "run_id",
        "event_type",
        "timestamp",
        "status",
        "duration_ms",
        "error_category",
    }


def test_sqlite_event_store_rejects_naive_timestamps_and_non_string_categories(tmp_path):
    store = SQLiteEventStore(tmp_path / "events.sqlite3")
    invalid_events = [
        make_event("run-invalid", "run_started", timestamp=datetime(2026, 10, 23)),
        make_event(
            "run-invalid",
            "run_failed",
            category=["private error detail"],
        ),
    ]

    for event in invalid_events:
        with pytest.raises(EventStoreError) as error:
            store.emit(event)
        assert error.value.category == "event_store_invalid_event"

    assert store.events_for_run("run-invalid") == []


def test_composite_sink_keeps_in_memory_compatibility_and_surfaces_write_failure():
    memory = InMemoryEventSink()

    class FailingSink:
        def emit(self, event):
            raise EventStoreError("event_store_write_failed")

    sink = CompositeEventSink((memory, FailingSink()))
    event = make_event("run-composite", "run_started")

    with pytest.raises(EventStoreError) as error:
        sink.emit(event)

    assert error.value.category == "event_store_write_failed"
    assert memory.events == [event]
