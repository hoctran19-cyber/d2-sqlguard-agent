from __future__ import annotations

import os
import sqlite3
from collections.abc import Mapping
from contextlib import closing
from dataclasses import dataclass, field
from datetime import UTC, datetime
from pathlib import Path
from typing import Protocol

EVENT_DB_PATH_ENV = "SQLGUARD_EVENT_DB_PATH"
SAFE_ERROR_CATEGORIES = frozenset(
    {
        "audit_error",
        "budget_exhausted",
        "cancelled",
        "canary_leak",
        "db_error",
        "db_permission_denied",
        "db_read_only_violation",
        "db_role_unconfigured",
        "db_schema_error",
        "db_syntax_error",
        "db_timeout",
        "db_unavailable",
        "event_sink_error",
        "internal_error",
        "invalid_request",
        "invalid_tool_input",
        "invalid_tool_output",
        "memory_error",
        "mcp_invalid_result",
        "mcp_tool_error",
        "mcp_transport_error",
        "output_check_error",
        "planner_call_budget_exhausted",
        "planner_error",
        "run_timeout",
        "security_gate_error",
        "security_rejection",
        "sql_attempt_budget_exhausted",
        "sql_error",
        "tool_call_budget_exhausted",
        "tool_error",
        "tool_exception",
        "tool_timeout",
        "unknown_role",
        "unknown_tool",
    }
)


def safe_error_category(category: object) -> str:
    """Return a stable error code, replacing untrusted messages with a generic category."""
    return (
        category
        if isinstance(category, str) and category in SAFE_ERROR_CATEGORIES
        else "tool_error"
    )


@dataclass(frozen=True)
class Event:
    run_id: str
    event_type: str
    timestamp: datetime = field(default_factory=lambda: datetime.now(UTC))
    status: str | None = None
    duration_ms: float | None = None
    error_category: str | None = None


class EventSink(Protocol):
    def emit(self, event: Event) -> None: ...


@dataclass
class InMemoryEventSink:
    events: list[Event] = field(default_factory=list)

    def emit(self, event: Event) -> None:
        self.events.append(event)


@dataclass(frozen=True)
class CompositeEventSink:
    """Fan events out to each sink, attempting all sinks before surfacing a failure."""

    sinks: tuple[EventSink, ...]

    def emit(self, event: Event) -> None:
        first_error: Exception | None = None
        for sink in self.sinks:
            try:
                sink.emit(event)
            except Exception as error:
                if first_error is None:
                    first_error = error
        if first_error is not None:
            raise first_error


class EventStoreError(Exception):
    """Safe persistence error category; does not contain SQLite details or paths."""

    def __init__(self, category: str) -> None:
        super().__init__(category)
        self.category = category


def default_event_db_path() -> Path:
    state_home = os.environ.get("XDG_STATE_HOME")
    base = Path(state_home).expanduser() if state_home else Path.home() / ".local" / "state"
    return base / "sqlguard" / "events.sqlite3"


class SQLiteEventStore:
    """SQLite-backed event sink using a short-lived connection for each operation."""

    def __init__(self, path: str | Path) -> None:
        configured = str(path).strip()
        if not configured or configured == ":memory:":
            raise EventStoreError("event_store_config_error")
        self.path = Path(configured).expanduser()
        try:
            self.path.parent.mkdir(parents=True, exist_ok=True)
            with closing(sqlite3.connect(self.path, timeout=5)) as connection:
                with connection:
                    connection.execute(
                        """
                        CREATE TABLE IF NOT EXISTS observability_events (
                            sequence INTEGER PRIMARY KEY AUTOINCREMENT,
                            run_id TEXT NOT NULL,
                            event_type TEXT NOT NULL,
                            timestamp TEXT NOT NULL,
                            status TEXT,
                            duration_ms REAL,
                            error_category TEXT
                        )
                        """
                    )
                    connection.execute(
                        """
                        CREATE INDEX IF NOT EXISTS
                            idx_observability_events_run_sequence
                        ON observability_events (run_id, sequence)
                        """
                    )
        except (OSError, sqlite3.Error):
            raise EventStoreError("event_store_unavailable") from None

    @classmethod
    def from_env(cls, env: Mapping[str, str] | None = None) -> SQLiteEventStore:
        env = os.environ if env is None else env
        path = env.get(EVENT_DB_PATH_ENV)
        return cls(path if path is not None else default_event_db_path())

    def emit(self, event: Event) -> None:
        if event.error_category is not None and (
            not isinstance(event.error_category, str)
            or event.error_category not in SAFE_ERROR_CATEGORIES
        ):
            raise EventStoreError("event_store_invalid_event")
        try:
            if event.timestamp.tzinfo is None or event.timestamp.utcoffset() is None:
                raise EventStoreError("event_store_invalid_event")
            timestamp = event.timestamp.astimezone(UTC).isoformat()
            with closing(sqlite3.connect(self.path, timeout=5)) as connection:
                with connection:
                    connection.execute(
                        """
                        INSERT INTO observability_events (
                            run_id, event_type, timestamp, status, duration_ms, error_category
                        ) VALUES (?, ?, ?, ?, ?, ?)
                        """,
                        (
                            event.run_id,
                            event.event_type,
                            timestamp,
                            event.status,
                            event.duration_ms,
                            event.error_category,
                        ),
                    )
        except EventStoreError:
            raise
        except (OSError, sqlite3.Error, OverflowError, ValueError):
            raise EventStoreError("event_store_write_failed") from None

    def events_for_run(self, run_id: str) -> list[Event]:
        try:
            with closing(sqlite3.connect(self.path, timeout=5)) as connection:
                rows = connection.execute(
                    """
                    SELECT run_id, event_type, timestamp, status, duration_ms, error_category
                    FROM observability_events
                    WHERE run_id = ?
                    ORDER BY sequence
                    """,
                    (run_id,),
                ).fetchall()
            return [
                Event(
                    run_id=run_id,
                    event_type=event_type,
                    timestamp=datetime.fromisoformat(timestamp).astimezone(UTC),
                    status=status,
                    duration_ms=duration_ms,
                    error_category=error_category,
                )
                for _, event_type, timestamp, status, duration_ms, error_category in rows
            ]
        except (OSError, sqlite3.Error, OverflowError, ValueError):
            raise EventStoreError("event_store_read_failed") from None
