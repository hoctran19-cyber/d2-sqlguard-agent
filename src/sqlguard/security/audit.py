from __future__ import annotations

import json
import threading
from dataclasses import asdict, dataclass, field
from datetime import UTC, datetime
from pathlib import Path
from typing import Protocol


@dataclass(frozen=True)
class AuditRecord:
    """One security decision or guarded execution.

    Records carry hashes and counts only: no SQL text, rows, question, credential or raw
    database error, so the audit trail can be shared as evidence without leaking data.
    """

    phase: str  # "gate" (decision only) or "execute" (decision + execution outcome)
    outcome: str  # allowed | denied | executed | db_error | blocked
    role: str
    policy_version: str
    gate_mode: str
    decision_kind: str
    run_id: str | None = None
    attempt: int = 0
    user_id: str = "anonymous"
    request_mode: str = "nl"
    violations: tuple[str, ...] = ()
    removed_columns: tuple[str, ...] = ()
    notices: tuple[str, ...] = ()
    input_hash: str | None = None
    query_hash: str | None = None
    error_category: str | None = None
    row_count: int | None = None
    truncated: bool | None = None
    result_bytes: int | None = None
    injection_flags: int = 0
    timestamp: str = field(default_factory=lambda: datetime.now(UTC).isoformat())

    def to_json(self) -> str:
        return json.dumps(asdict(self), ensure_ascii=False, sort_keys=True)


class AuditSink(Protocol):
    def record(self, record: AuditRecord) -> None: ...


@dataclass
class InMemoryAuditSink:
    records: list[AuditRecord] = field(default_factory=list)

    def record(self, record: AuditRecord) -> None:
        self.records.append(record)


class JsonlAuditSink:
    """Append-only JSON Lines audit file; each write is flushed before returning."""

    def __init__(self, path: str | Path) -> None:
        self._path = Path(path)
        self._path.parent.mkdir(parents=True, exist_ok=True)
        self._lock = threading.Lock()

    def record(self, record: AuditRecord) -> None:
        line = record.to_json() + "\n"
        with self._lock, self._path.open("a", encoding="utf-8") as handle:
            handle.write(line)
            handle.flush()

    def read(self) -> list[dict]:
        if not self._path.exists():
            return []
        with self._path.open(encoding="utf-8") as handle:
            return [json.loads(line) for line in handle if line.strip()]
