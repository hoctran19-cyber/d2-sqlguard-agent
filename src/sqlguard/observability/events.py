from __future__ import annotations

import asyncio
import logging
import os
import sqlite3
import threading
import time
from collections import OrderedDict
from collections.abc import Mapping
from contextlib import closing
from dataclasses import dataclass, field, replace
from datetime import UTC, datetime
from pathlib import Path
from typing import Protocol, TypeAlias
from uuid import uuid4

logger = logging.getLogger(__name__)

EVENT_DB_PATH_ENV = "SQLGUARD_EVENT_DB_PATH"
DEFAULT_HISTORY_LIMIT = 20
MAX_HISTORY_LIMIT = 100
MAX_HISTORY_OFFSET = 1_000_000
JSONValue: TypeAlias = str | int | float | bool | None | list["JSONValue"] | dict[str, "JSONValue"]
TERMINAL_EVENT_TYPES = (
    "run_completed",
    "run_refused",
    "run_failed",
    "run_timed_out",
    "budget_exhausted",
)
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


@dataclass(frozen=True)
class LiveEvent(Event):
    module: str | None = None
    step: str | None = None
    attempt_id: str | None = None
    related_attempt_id: str | None = None
    retry_count: int | None = None
    data: Mapping[str, JSONValue] | None = None
    input: Mapping[str, JSONValue] | None = None
    output: Mapping[str, JSONValue] | None = None
    evidence: Mapping[str, JSONValue] = field(default_factory=dict)


@dataclass
class _LiveRun:
    created_at: float
    events: list[tuple[int, Event]] = field(default_factory=list)
    subscribers: dict[
        str, tuple[asyncio.AbstractEventLoop, asyncio.Queue[tuple[int, Event] | None]]
    ] = field(default_factory=dict)
    next_sequence: int = 1
    completed: bool = False
    capture_complete: bool = True


@dataclass(frozen=True)
class LiveEventSubscription:
    replay: tuple[tuple[int, Event], ...]
    queue: asyncio.Queue[tuple[int, Event] | None]
    completed: bool
    subscriber_id: str
    replay_gap: bool = False


class LiveEventHub:
    """In-process, run-scoped event fan-out with bounded replay for SSE reconnects."""

    def __init__(
        self,
        *,
        max_runs: int = 256,
        max_events_per_run: int = 512,
        retention_seconds: float = 600,
    ) -> None:
        self._max_runs = max_runs
        self._max_events_per_run = max_events_per_run
        self._retention_seconds = retention_seconds
        self._lock = threading.RLock()
        self._runs: OrderedDict[str, _LiveRun] = OrderedDict()

    def prepare(self, run_id: str) -> None:
        with self._lock:
            self._prune_expired()
            if run_id not in self._runs and len(self._runs) >= self._max_runs:
                self._evict_completed()
            if run_id not in self._runs and len(self._runs) >= self._max_runs:
                raise RuntimeError("live_event_capacity_exhausted")
            self._runs.setdefault(run_id, _LiveRun(created_at=time.monotonic()))

    def subscribe(self, run_id: str, last_event_id: int = 0) -> LiveEventSubscription:
        loop = asyncio.get_running_loop()
        queue: asyncio.Queue[tuple[int, Event] | None] = asyncio.Queue()
        subscriber_id = str(uuid4())
        with self._lock:
            self.prepare(run_id)
            run = self._runs[run_id]
            run.subscribers[subscriber_id] = (loop, queue)
            replay = tuple(
                (sequence, event) for sequence, event in run.events if sequence > last_event_id
            )
            replay_gap = bool(run.events and last_event_id < run.events[0][0] - 1)
            return LiveEventSubscription(replay, queue, run.completed, subscriber_id, replay_gap)

    def unsubscribe(self, run_id: str, subscriber_id: str) -> None:
        with self._lock:
            run = self._runs.get(run_id)
            if run is not None:
                run.subscribers.pop(subscriber_id, None)

    def publish(self, event: Event) -> None:
        with self._lock:
            self.prepare(event.run_id)
            run = self._runs[event.run_id]
            if run.completed:
                return
            snapshot = (
                replace(
                    event,
                    data=dict(event.data) if event.data is not None else None,
                    input=dict(event.input) if event.input is not None else None,
                    output=dict(event.output) if event.output is not None else None,
                    evidence=dict(event.evidence),
                )
                if isinstance(event, LiveEvent)
                else event
            )
            sequence = run.next_sequence
            run.next_sequence += 1
            run.events.append((sequence, snapshot))
            if len(run.events) > self._max_events_per_run:
                del run.events[: len(run.events) - self._max_events_per_run]
                run.capture_complete = False
            subscribers = tuple(run.subscribers.values())
            if event.event_type in TERMINAL_EVENT_TYPES:
                run.completed = True
        for loop, queue in subscribers:
            try:
                loop.call_soon_threadsafe(queue.put_nowait, (sequence, snapshot))
                if event.event_type in TERMINAL_EVENT_TYPES:
                    loop.call_soon_threadsafe(queue.put_nowait, None)
            except RuntimeError:
                with self._lock:
                    run = self._runs.get(event.run_id)
                    if run is not None:
                        run.capture_complete = False
                continue

    def mark_incomplete(self, run_id: str) -> None:
        with self._lock:
            run = self._runs.get(run_id)
            if run is not None:
                run.capture_complete = False

    def snapshot(self, run_id: str) -> tuple[tuple[tuple[int, Event], ...], str]:
        with self._lock:
            run = self._runs.get(run_id)
            if run is None:
                return (), "unknown"
            state = "complete" if run.completed and run.capture_complete else "incomplete"
            return tuple(run.events), state

    def complete(self, run_id: str) -> None:
        with self._lock:
            run = self._runs.get(run_id)
            if run is None or run.completed:
                return
            run.completed = True
            subscribers = tuple(run.subscribers.values())
        for loop, queue in subscribers:
            try:
                loop.call_soon_threadsafe(queue.put_nowait, None)
            except RuntimeError:
                continue

    def _prune_expired(self) -> None:
        cutoff = time.monotonic() - self._retention_seconds
        expired = [
            run_id
            for run_id, run in self._runs.items()
            if run.completed and not run.subscribers and run.created_at < cutoff
        ]
        for run_id in expired:
            del self._runs[run_id]

    def _evict_completed(self) -> None:
        for run_id, run in tuple(self._runs.items()):
            if run.completed and not run.subscribers:
                del self._runs[run_id]
                return


@dataclass(frozen=True)
class LiveEventSink:
    """Best-effort event sink; subscriber and transport failures never fail agent execution."""

    hub: LiveEventHub

    def emit(self, event: Event) -> None:
        try:
            self.hub.publish(event)
        except Exception:
            try:
                self.hub.mark_incomplete(event.run_id)
            except Exception:
                logger.warning(
                    "Live trace capture failed and its incomplete status could not be recorded."
                )
            return


class EventSink(Protocol):
    def emit(self, event: Event) -> None: ...


@dataclass
class InMemoryEventSink:
    events: list[Event] = field(default_factory=list)

    def emit(self, event: Event) -> None:
        self.events.append(
            Event(
                run_id=event.run_id,
                event_type=event.event_type,
                timestamp=event.timestamp,
                status=event.status,
                duration_ms=event.duration_ms,
                error_category=event.error_category,
            )
        )


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
                    error_category=(
                        safe_error_category(error_category) if error_category is not None else None
                    ),
                )
                for _, event_type, timestamp, status, duration_ms, error_category in rows
            ]
        except (OSError, sqlite3.Error, OverflowError, ValueError):
            raise EventStoreError("event_store_read_failed") from None

    def list_runs(self, limit: int = DEFAULT_HISTORY_LIMIT, offset: int = 0) -> dict[str, object]:
        if type(limit) is not int or not 1 <= limit <= MAX_HISTORY_LIMIT:
            raise ValueError("limit is outside the allowed range")
        if type(offset) is not int or not 0 <= offset <= MAX_HISTORY_OFFSET:
            raise ValueError("offset is outside the allowed range")

        terminal_types = ", ".join("?" for _ in TERMINAL_EVENT_TYPES)
        try:
            with closing(sqlite3.connect(self.path, timeout=5)) as connection:
                [(total,)] = connection.execute(
                    "SELECT COUNT(DISTINCT run_id) FROM observability_events"
                ).fetchall()
                rows = connection.execute(
                    f"""
                    WITH run_summary AS (
                        SELECT
                            run_id,
                            MIN(CASE WHEN event_type = 'run_started' THEN timestamp END)
                                AS started_at,
                            COUNT(*) AS event_count,
                            MAX(julianday(timestamp)) AS latest_time,
                            MAX(sequence) AS latest_sequence
                        FROM observability_events
                        GROUP BY run_id
                    )
                    SELECT
                        summary.run_id,
                        summary.started_at,
                        summary.event_count,
                        (
                            SELECT timestamp FROM observability_events AS terminal
                            WHERE terminal.run_id = summary.run_id
                                AND terminal.event_type IN ({terminal_types})
                            ORDER BY terminal.sequence DESC LIMIT 1
                        ) AS ended_at,
                        (
                            SELECT status FROM observability_events AS terminal
                            WHERE terminal.run_id = summary.run_id
                                AND terminal.event_type IN ({terminal_types})
                            ORDER BY terminal.sequence DESC LIMIT 1
                        ) AS status,
                        (
                            SELECT duration_ms FROM observability_events AS terminal
                            WHERE terminal.run_id = summary.run_id
                                AND terminal.event_type IN ({terminal_types})
                            ORDER BY terminal.sequence DESC LIMIT 1
                        ) AS duration_ms,
                        (
                            SELECT error_category FROM observability_events AS terminal
                            WHERE terminal.run_id = summary.run_id
                                AND terminal.event_type IN ({terminal_types})
                            ORDER BY terminal.sequence DESC LIMIT 1
                        ) AS error_category
                    FROM run_summary AS summary
                    ORDER BY summary.latest_time DESC,
                        summary.latest_sequence DESC, summary.run_id ASC
                    LIMIT ? OFFSET ?
                    """,
                    (
                        *TERMINAL_EVENT_TYPES,
                        *TERMINAL_EVENT_TYPES,
                        *TERMINAL_EVENT_TYPES,
                        *TERMINAL_EVENT_TYPES,
                        limit,
                        offset,
                    ),
                ).fetchall()

            items = []
            for run_id, started_at, event_count, ended_at, status, duration_ms, category in rows:
                items.append(
                    {
                        "run_id": run_id,
                        "started_at": _utc_isoformat(started_at),
                        "ended_at": _utc_isoformat(ended_at),
                        "event_count": event_count,
                        "status": status,
                        "duration_ms": duration_ms,
                        "error_category": (
                            safe_error_category(category) if category is not None else None
                        ),
                    }
                )
            return {"items": items, "total": total, "limit": limit, "offset": offset}
        except (OSError, sqlite3.Error, OverflowError, ValueError):
            raise EventStoreError("event_store_read_failed") from None


def _utc_isoformat(value: str | None) -> str | None:
    if value is None:
        return None
    return datetime.fromisoformat(value).astimezone(UTC).isoformat()
