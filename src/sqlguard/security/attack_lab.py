"""Attack Lab: the demo-only write surface that plants injection payloads in ``note`` columns.

This is deliberately *not* an agent tool. The backend calls it for the ``/demo/attack-lab``
route; it writes through the dedicated ``sqlguard_note_writer`` credential, which can only
``UPDATE (note)`` on allowlisted tables. Every mutation:

* requires the lab to be enabled (demo profile) and a target on the allowlist;
* is refused while an agent run is active, so a run never sees a note change mid-flight;
* uses optimistic concurrency (``expected_revision``) so two presenters cannot clobber each other;
* is read back and verified, recorded as a revision, and audited with hashes only.

``restore`` returns a note to its baseline (the value seen before the first lab write) or to any
earlier revision. Revisions live in process memory: restart the backend only after restoring,
or re-seed the demo database (see docs/threat-model/ATTACK_LAB.md).
"""

from __future__ import annotations

import asyncio
import hashlib
import json
import unicodedata
from collections.abc import Callable
from dataclasses import asdict, dataclass, field
from datetime import UTC, datetime
from typing import Protocol

# Fixed statements per table: identifiers never come from the request.
NOTE_SQL: dict[str, tuple[str, str]] = {
    "customers": (
        "SELECT note FROM customers WHERE customer_id = %s",
        "UPDATE customers SET note = %s WHERE customer_id = %s",
    ),
    "orders": (
        "SELECT note FROM orders WHERE order_id = %s",
        "UPDATE orders SET note = %s WHERE order_id = %s",
    ),
}
DEFAULT_TARGETS: frozenset[tuple[str, int]] = frozenset(
    (table, row_id) for table in ("customers", "orders") for row_id in (1, 2, 3)
)


class LabError(Exception):
    def __init__(self, category: str) -> None:
        super().__init__(category)
        self.category = category


class NoteWriter(Protocol):
    async def read_note(self, table: str, row_id: int) -> str | None: ...

    async def write_note(self, table: str, row_id: int, value: str | None) -> None: ...


@dataclass(frozen=True)
class NoteRevision:
    target: str
    revision: int
    action: str  # baseline | save | restore
    content_hash: str | None
    length: int
    user_id: str
    timestamp: str


@dataclass(frozen=True)
class LabAuditRecord:
    action: str
    outcome: str  # ok | denied | failed
    target: str
    user_id: str
    category: str | None = None
    revision_before: int | None = None
    revision_after: int | None = None
    hash_before: str | None = None
    hash_after: str | None = None
    length: int | None = None
    phase: str = "attack_lab"
    timestamp: str = field(default_factory=lambda: datetime.now(UTC).isoformat())

    def to_json(self) -> str:
        return json.dumps(asdict(self), ensure_ascii=False, sort_keys=True)


class AttackLab:
    def __init__(
        self,
        writer: NoteWriter,
        *,
        enabled: bool,
        targets: frozenset[tuple[str, int]] = DEFAULT_TARGETS,
        audit=None,
        run_active: Callable[[], bool] = lambda: False,
        max_length: int = 2000,
    ) -> None:
        unknown = {table for table, _ in targets} - set(NOTE_SQL)
        if unknown:
            raise ValueError(f"No note statement for tables: {sorted(unknown)}")
        self._writer = writer
        self._enabled = enabled
        self._targets = targets
        self._audit = audit
        self._run_active = run_active
        self._max_length = max_length
        self._lock = asyncio.Lock()
        self._revisions: dict[str, list[NoteRevision]] = {}
        self._contents: dict[tuple[str, int], str | None] = {}

    async def get(self, target: str) -> dict:
        table, row_id = self._parse(target, action="read", user_id="-")
        async with self._lock:
            current = await self._ensure_baseline(table, row_id, user_id="system")
            content = self._contents[(target, current.revision)]
        return {
            "target": target,
            "revision": current.revision,
            "content": content,
            "baseline_revision": 0,
        }

    def history(self, target: str) -> list[NoteRevision]:
        return list(self._revisions.get(target, ()))

    def current_revision(self, target: str) -> int | None:
        revisions = self._revisions.get(target)
        return revisions[-1].revision if revisions else None

    async def save(
        self, target: str, content: str | None, *, expected_revision: int, user_id: str
    ) -> NoteRevision:
        table, row_id = self._parse(target, action="save", user_id=user_id)
        self._validate(content, target=target, user_id=user_id)
        return await self._mutate(
            "save", table, row_id, content, expected_revision=expected_revision, user_id=user_id
        )

    async def restore(
        self,
        target: str,
        *,
        expected_revision: int,
        user_id: str,
        to_revision: int = 0,
    ) -> NoteRevision:
        table, row_id = self._parse(target, action="restore", user_id=user_id)
        return await self._mutate(
            "restore",
            table,
            row_id,
            None,
            expected_revision=expected_revision,
            user_id=user_id,
            to_revision=to_revision,
        )

    async def _mutate(
        self, action, table, row_id, content, *, expected_revision, user_id, to_revision=None
    ):
        target = f"{table}.{row_id}"
        async with self._lock:
            if self._run_active():
                self._deny(action, target, user_id, "run_active")
            current = await self._ensure_baseline(table, row_id, user_id=user_id)
            if expected_revision != current.revision:
                self._deny(action, target, user_id, "revision_conflict", current=current)
            if to_revision is not None:
                if (target, to_revision) not in self._contents:
                    self._deny(action, target, user_id, "unknown_revision", current=current)
                content = self._contents[(target, to_revision)]
            try:
                await self._writer.write_note(table, row_id, content)
                stored = await self._writer.read_note(table, row_id)
            except Exception:
                self._record(action, "failed", target, user_id, "write_failed", current=current)
                raise LabError("write_failed") from None
            if stored != content:
                self._record(action, "failed", target, user_id, "write_unverified", current=current)
                raise LabError("write_unverified")
            revision = NoteRevision(
                target=target,
                revision=current.revision + 1,
                action=action,
                content_hash=_hash(content),
                length=len(content or ""),
                user_id=user_id,
                timestamp=datetime.now(UTC).isoformat(),
            )
            self._revisions[target].append(revision)
            self._contents[(target, revision.revision)] = content
            self._record(action, "ok", target, user_id, None, current=current, after=revision)
            return revision

    async def _ensure_baseline(self, table: str, row_id: int, *, user_id: str) -> NoteRevision:
        target = f"{table}.{row_id}"
        if target not in self._revisions:
            try:
                content = await self._writer.read_note(table, row_id)
            except Exception:
                raise LabError("read_failed") from None
            baseline = NoteRevision(
                target=target,
                revision=0,
                action="baseline",
                content_hash=_hash(content),
                length=len(content or ""),
                user_id=user_id,
                timestamp=datetime.now(UTC).isoformat(),
            )
            self._revisions[target] = [baseline]
            self._contents[(target, 0)] = content
        return self._revisions[target][-1]

    def _parse(self, target: str, *, action: str, user_id: str) -> tuple[str, int]:
        if not self._enabled:
            self._deny(action, str(target)[:64], user_id, "lab_disabled")
        table, _, raw_id = str(target).partition(".")
        if not raw_id.isdigit() or (table, int(raw_id)) not in self._targets:
            self._deny(action, str(target)[:64], user_id, "target_not_allowed")
        return table, int(raw_id)

    def _validate(self, content: str | None, *, target: str, user_id: str) -> None:
        if content is None:
            return
        if not isinstance(content, str) or len(content) > self._max_length:
            self._deny("save", target, user_id, "invalid_payload")
        if any(
            char not in "\n\t" and unicodedata.category(char) in {"Cc", "Cs", "Co", "Cn"}
            for char in content
        ):
            self._deny("save", target, user_id, "invalid_payload")

    def _deny(self, action, target, user_id, category, *, current=None):
        self._record(action, "denied", target, user_id, category, current=current)
        raise LabError(category)

    def _record(self, action, outcome, target, user_id, category, *, current=None, after=None):
        if self._audit is None:
            return
        self._audit.record(
            LabAuditRecord(
                action=action,
                outcome=outcome,
                target=target,
                user_id=user_id,
                category=category,
                revision_before=current.revision if current else None,
                revision_after=after.revision if after else None,
                hash_before=current.content_hash if current else None,
                hash_after=after.content_hash if after else None,
                length=after.length if after else None,
            )
        )


class PostgresNoteWriter:
    """Writes with the note-writer credential (``SQLGUARD_DB_DSN_NOTE_WRITER``) only."""

    def __init__(self, dsn: str) -> None:
        self._dsn = dsn

    async def read_note(self, table: str, row_id: int) -> str | None:
        return await asyncio.to_thread(self._run, NOTE_SQL[table][0], (row_id,), False)

    async def write_note(self, table: str, row_id: int, value: str | None) -> None:
        await asyncio.to_thread(self._run, NOTE_SQL[table][1], (value, row_id), True)

    def _run(self, sql: str, params: tuple, write: bool):
        import psycopg

        with psycopg.connect(self._dsn, connect_timeout=5) as conn, conn.cursor() as cursor:
            cursor.execute(sql, params)
            if write:
                if cursor.rowcount != 1:
                    raise LabError("target_missing")
                conn.commit()
                return None
            row = cursor.fetchone()
            if row is None:
                raise LabError("target_missing")
            return row[0]


def _hash(content: str | None) -> str | None:
    if content is None:
        return None
    return hashlib.sha256(content.encode("utf-8")).hexdigest()
