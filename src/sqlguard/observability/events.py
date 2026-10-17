from __future__ import annotations

from dataclasses import dataclass, field
from datetime import UTC, datetime
from typing import Protocol


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
