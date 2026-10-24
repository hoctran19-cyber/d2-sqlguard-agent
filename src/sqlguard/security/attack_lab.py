"""Attack Lab: the demo-only write surface that plants injection payloads in note columns.

This is deliberately *not* an agent tool. The backend (or the presenter CLI below) calls it; it
writes only to a **lab copy** of the reviewed SQLite database, never to the original, through
``SQLiteNoteWriter``, whose SQLite authorizer allows nothing but updating the note column of the
tables listed in the policy's ``note_targets``. Every mutation:

* requires the lab to be enabled (demo profile) and a target on the allowlist;
* is refused while an agent run is active, so a run never sees a note change mid-flight;
* uses optimistic concurrency (``expected_revision``) so two presenters cannot clobber each other;
* is read back and verified, recorded as a revision, and audited with hashes only.

``restore`` returns a note to its baseline (the value seen before the first lab write) or to any
earlier revision. With ``SQLiteRevisionStore`` the revisions live in a sidecar file next to the
lab copy, so they survive a backend restart; see docs/threat-model/ATTACK_LAB.md.
"""

from __future__ import annotations

import argparse
import asyncio
import getpass
import hashlib
import json
import os
import sqlite3
import sys
import unicodedata
from collections.abc import Callable, Iterator, Mapping, Sequence
from contextlib import AbstractContextManager, asynccontextmanager, closing, contextmanager
from dataclasses import asdict, dataclass, field
from datetime import UTC, datetime
from pathlib import Path
from typing import Protocol

from sqlguard.security.business_database import BUSINESS_DATABASE_ENV
from sqlguard.security.policy import RolePolicy, load_default_policy, load_policy
from sqlguard.security.schema_preflight import preflight_financial_sqlite

ENABLED_ENV = "SQLGUARD_ATTACK_LAB_ENABLED"
LAB_DB_ENV = "SQLGUARD_ATTACK_LAB_DB"
TARGETS_ENV = "SQLGUARD_ATTACK_LAB_TARGETS"
LAB_POLICY = "business_financial_v1"
MARKER_SUFFIX = ".lab.json"
REVISIONS_SUFFIX = ".lab-revisions.sqlite"

_REVISION_SCHEMA = """
CREATE TABLE revisions (
    target TEXT NOT NULL,
    revision INTEGER NOT NULL,
    action TEXT NOT NULL,
    content TEXT,
    content_hash TEXT,
    length INTEGER NOT NULL,
    user_id TEXT NOT NULL,
    timestamp TEXT NOT NULL,
    PRIMARY KEY (target, revision)
)
"""


def note_statements(policy: RolePolicy) -> dict[str, tuple[str, str]]:
    """Fixed read/update statements per note table. Identifiers come from the reviewed policy
    file, never from the request; values are always bound parameters."""
    statements = {}
    for table, key in policy.note_targets.items():
        column = policy.note_column(table)
        statements[table] = (
            f'SELECT "{column}" FROM "{table}" WHERE "{key}" = ?',
            f'UPDATE "{table}" SET "{column}" = ? WHERE "{key}" = ?',
        )
    return statements


def parse_targets(text: str) -> frozenset[tuple[str, int]]:
    """Parse ``"account.3,order.29407"`` (e.g. from ``SQLGUARD_ATTACK_LAB_TARGETS``)."""
    targets = set()
    for item in filter(None, (part.strip() for part in text.split(","))):
        table, _, raw_id = item.partition(".")
        if not table or not raw_id.isdigit():
            raise ValueError(f"Invalid Attack Lab target {item!r}")
        targets.add((table.casefold(), int(raw_id)))
    return frozenset(targets)


def marker_path(lab_db: str | Path) -> Path:
    return Path(f"{Path(lab_db).expanduser()}{MARKER_SUFFIX}")


def revisions_path(lab_db: str | Path) -> Path:
    return Path(f"{Path(lab_db).expanduser()}{REVISIONS_SUFFIX}")


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


class RevisionLog(Protocol):
    def history(self, target: str) -> list[NoteRevision]: ...

    def content(self, target: str, revision: int) -> str | None: ...

    def append(self, revision: NoteRevision, content: str | None) -> None: ...


class RevisionStore(RevisionLog, Protocol):
    def transaction(self) -> AbstractContextManager[RevisionLog]: ...


class InMemoryRevisionStore:
    """Revisions in process memory; they are lost when the process exits."""

    def __init__(self) -> None:
        self._revisions: dict[str, list[NoteRevision]] = {}
        self._contents: dict[tuple[str, int], str | None] = {}

    @contextmanager
    def transaction(self) -> Iterator[RevisionLog]:
        yield self

    def history(self, target: str) -> list[NoteRevision]:
        return list(self._revisions.get(target, ()))

    def content(self, target: str, revision: int) -> str | None:
        return self._contents[(target, revision)]

    def append(self, revision: NoteRevision, content: str | None) -> None:
        self._revisions.setdefault(revision.target, []).append(revision)
        self._contents[(revision.target, revision.revision)] = content


class SQLiteRevisionStore:
    """Revisions in a sidecar SQLite file next to the lab copy, so restore survives a restart.

    A mutation holds ``BEGIN IMMEDIATE`` on the sidecar from reading the current revision to
    recording the new one, which also serializes the web backend and the presenter CLI. Stored
    contents are checked against their hash on every read; a mismatch fails closed.
    """

    def __init__(self, path: str | Path) -> None:
        database = Path(path).expanduser()
        if not database.is_file():
            raise LabError("revision_store_missing")
        # mode=rw: never create a stray empty store when the path is wrong.
        self._uri = f"{database.resolve().as_uri()}?mode=rw"

    @classmethod
    def create(cls, path: str | Path) -> SQLiteRevisionStore:
        database = Path(path).expanduser()
        if database.exists():
            raise FileExistsError("revision store already exists")
        with closing(sqlite3.connect(database)) as connection:
            connection.execute(_REVISION_SCHEMA)
            connection.commit()
        return cls(database)

    @contextmanager
    def transaction(self) -> Iterator[RevisionLog]:
        connection = self._connect()
        try:
            connection.execute("BEGIN IMMEDIATE")
            yield _SQLiteRevisionLog(connection)
            connection.execute("COMMIT")
        finally:
            if connection.in_transaction:
                connection.execute("ROLLBACK")
            connection.close()

    def history(self, target: str) -> list[NoteRevision]:
        with closing(self._connect()) as connection:
            return _SQLiteRevisionLog(connection).history(target)

    def content(self, target: str, revision: int) -> str | None:
        with closing(self._connect()) as connection:
            return _SQLiteRevisionLog(connection).content(target, revision)

    def append(self, revision: NoteRevision, content: str | None) -> None:
        with self.transaction() as log:
            log.append(revision, content)

    def _connect(self) -> sqlite3.Connection:
        # The connection is used sequentially across awaits, possibly from several threads.
        return sqlite3.connect(
            self._uri, uri=True, timeout=2.0, isolation_level=None, check_same_thread=False
        )


class _SQLiteRevisionLog:
    def __init__(self, connection: sqlite3.Connection) -> None:
        self._connection = connection

    def history(self, target: str) -> list[NoteRevision]:
        rows = self._connection.execute(
            "SELECT target, revision, action, content_hash, length, user_id, timestamp "
            "FROM revisions WHERE target = ? ORDER BY revision",
            (target,),
        ).fetchall()
        if [row[1] for row in rows] != list(range(len(rows))):
            raise LabError("revision_store_invalid")
        return [NoteRevision(*row) for row in rows]

    def content(self, target: str, revision: int) -> str | None:
        row = self._connection.execute(
            "SELECT content, content_hash FROM revisions WHERE target = ? AND revision = ?",
            (target, revision),
        ).fetchone()
        if row is None:
            raise KeyError((target, revision))
        if _hash(row[0]) != row[1]:
            raise LabError("revision_store_invalid")
        return row[0]

    def append(self, revision: NoteRevision, content: str | None) -> None:
        self._connection.execute(
            "INSERT INTO revisions VALUES (?, ?, ?, ?, ?, ?, ?, ?)",
            (
                revision.target,
                revision.revision,
                revision.action,
                content,
                revision.content_hash,
                revision.length,
                revision.user_id,
                revision.timestamp,
            ),
        )


class AttackLab:
    def __init__(
        self,
        writer: NoteWriter,
        *,
        enabled: bool,
        targets: frozenset[tuple[str, int]],
        policy: RolePolicy | None = None,
        audit=None,
        run_active: Callable[[], bool] = lambda: False,
        max_length: int = 2000,
        store: RevisionStore | None = None,
    ) -> None:
        allowed = set((policy or load_default_policy()).note_targets)
        unknown = {table for table, _ in targets} - allowed
        if unknown:
            raise ValueError(f"Tables are not note targets in the policy: {sorted(unknown)}")
        self._writer = writer
        self._enabled = enabled
        self._targets = targets
        self._audit = audit
        self._run_active = run_active
        self._max_length = max_length
        self._store = store or InMemoryRevisionStore()
        self._lock = asyncio.Lock()

    @property
    def targets(self) -> list[str]:
        return sorted(f"{table}.{row_id}" for table, row_id in self._targets)

    async def get(self, target: str) -> dict:
        table, row_id = self._parse(target, action="read", user_id="-")
        target = f"{table}.{row_id}"
        async with self._session("read", target, "-") as log:
            current = await self._ensure_baseline(log, table, row_id, user_id="system")
            content = log.content(target, current.revision)
        return {
            "target": target,
            "revision": current.revision,
            "content": content,
            "baseline_revision": 0,
        }

    def history(self, target: str) -> list[NoteRevision]:
        try:
            return self._store.history(target)
        except sqlite3.Error:
            raise LabError("revision_store_failed") from None

    def current_revision(self, target: str) -> int | None:
        revisions = self.history(target)
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

    @asynccontextmanager
    async def _session(self, action: str, target: str, user_id: str):
        async with self._lock:
            try:
                with self._store.transaction() as log:
                    yield log
            except sqlite3.Error:
                self._record(action, "failed", target, user_id, "revision_store_failed")
                raise LabError("revision_store_failed") from None

    async def _mutate(
        self, action, table, row_id, content, *, expected_revision, user_id, to_revision=None
    ):
        target = f"{table}.{row_id}"
        async with self._session(action, target, user_id) as log:
            if self._run_active():
                self._deny(action, target, user_id, "run_active")
            current = await self._ensure_baseline(log, table, row_id, user_id=user_id)
            if expected_revision != current.revision:
                self._deny(action, target, user_id, "revision_conflict", current=current)
            if to_revision is not None:
                try:
                    content = log.content(target, to_revision)
                except KeyError:
                    self._deny(action, target, user_id, "unknown_revision", current=current)
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
            log.append(revision, content)
        self._record(action, "ok", target, user_id, None, current=current, after=revision)
        return revision

    async def _ensure_baseline(
        self, log: RevisionLog, table: str, row_id: int, *, user_id: str
    ) -> NoteRevision:
        target = f"{table}.{row_id}"
        revisions = log.history(target)
        if revisions:
            return revisions[-1]
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
        log.append(baseline, content)
        return baseline

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


def build_note_authorizer(policy: RolePolicy) -> Callable[..., int]:
    """Authorizer for the lab writer: read the key and note column, update the note column of a
    ``note_targets`` table, and nothing else (no other column, table, DDL, ATTACH or PRAGMA)."""
    updatable = {(table, policy.note_column(table)) for table in policy.note_targets}
    readable = updatable | set(policy.note_targets.items())

    def authorize(action, arg1, arg2, database, source) -> int:
        column = ((arg1 or "").casefold(), (arg2 or "").casefold())
        if action in (sqlite3.SQLITE_SELECT, sqlite3.SQLITE_TRANSACTION):
            return sqlite3.SQLITE_OK
        if action == sqlite3.SQLITE_READ and database == "main" and column in readable:
            return sqlite3.SQLITE_OK
        if action == sqlite3.SQLITE_UPDATE and database == "main" and column in updatable:
            return sqlite3.SQLITE_OK
        return sqlite3.SQLITE_DENY

    return authorize


class SQLiteNoteWriter:
    """Rewrites note cells of a lab copy made by ``create_lab_copy``; refuses any other file."""

    def __init__(self, path: str | Path, policy: RolePolicy | None = None) -> None:
        policy = policy or load_default_policy()
        database = Path(path).expanduser()
        if not database.is_file():
            raise LabError("lab_db_missing")
        _check_marker(database, policy)
        # mode=rw: a wrong path must fail instead of creating an empty database.
        self._uri = f"{database.resolve().as_uri()}?mode=rw"
        self._sql = note_statements(policy)
        self._authorizer = build_note_authorizer(policy)

    async def read_note(self, table: str, row_id: int) -> str | None:
        return await asyncio.to_thread(self._run, self._sql[table][0], (row_id,), False)

    async def write_note(self, table: str, row_id: int, value: str | None) -> None:
        await asyncio.to_thread(self._run, self._sql[table][1], (value, row_id), True)

    def _run(self, sql: str, params: tuple, write: bool):
        with closing(sqlite3.connect(self._uri, uri=True, timeout=5.0)) as connection:
            connection.set_authorizer(self._authorizer)
            cursor = connection.execute(sql, params)
            if write:
                if cursor.rowcount != 1:
                    connection.rollback()
                    raise LabError("target_missing")
                connection.commit()
                return None
            row = cursor.fetchone()
            if row is None:
                raise LabError("target_missing")
            return row[0]


def create_lab_copy(
    source: str | Path, output: str | Path, *, policy: RolePolicy | None = None
) -> Path:
    """Copy a preflight-valid financial database for the lab, with its marker and an empty
    revision store. Existing files are never overwritten and the source is never modified."""
    policy = policy or load_policy(LAB_POLICY)
    source_path = Path(source).expanduser()
    output_path = Path(output).expanduser()
    if not preflight_financial_sqlite(source_path).valid:
        raise LabError("lab_source_invalid")
    if _same_file(source_path, output_path):
        raise LabError("lab_db_not_a_copy")
    for path in (output_path, marker_path(output_path), revisions_path(output_path)):
        if path.exists():
            raise FileExistsError("lab copy already exists")
    output_path.parent.mkdir(parents=True, exist_ok=True)
    try:
        with (
            closing(sqlite3.connect(f"{source_path.resolve().as_uri()}?mode=ro", uri=True)) as src,
            closing(sqlite3.connect(output_path)) as dst,
        ):
            src.backup(dst)
        SQLiteRevisionStore.create(revisions_path(output_path))
        marker = {
            "source": str(source_path.resolve()),
            "source_sha256": _file_hash(source_path),
            "copy_sha256": _file_hash(output_path),
            "policy_version": policy.version,
            "created_at": datetime.now(UTC).isoformat(),
        }
        with marker_path(output_path).open("x", encoding="utf-8") as handle:
            json.dump(marker, handle, indent=2)
    except BaseException:
        for path in (output_path, marker_path(output_path), revisions_path(output_path)):
            path.unlink(missing_ok=True)
        raise
    return output_path


def attack_lab_from_env(
    env: Mapping[str, str] | None = None,
    *,
    audit=None,
    run_active: Callable[[], bool] = lambda: False,
    policy: RolePolicy | None = None,
) -> AttackLab | None:
    """The business-policy lab, or ``None`` unless ``SQLGUARD_ATTACK_LAB_ENABLED=1``.

    Enabled but misconfigured fails closed with a ``LabError``: the lab database must be a lab
    copy that passes the schema preflight, and it must be the very file the business agent reads
    (``SQLGUARD_BUSINESS_FINANCIAL_DB``), otherwise a payload would never reach the agent.
    """
    env = os.environ if env is None else env
    if env.get(ENABLED_ENV, "").strip() != "1":
        return None
    lab_db = env.get(LAB_DB_ENV, "").strip()
    if not lab_db:
        raise LabError("lab_not_configured")
    business_db = env.get(BUSINESS_DATABASE_ENV, "").strip()
    if not business_db or not _same_file(Path(business_db), Path(lab_db)):
        raise LabError("lab_db_mismatch")
    if not preflight_financial_sqlite(lab_db).valid:
        raise LabError("lab_db_invalid")
    policy = policy or load_policy(LAB_POLICY)
    try:
        targets = parse_targets(env.get(TARGETS_ENV, ""))
    except ValueError:
        raise LabError("lab_targets_invalid") from None
    if not {table for table, _ in targets} <= set(policy.note_targets):
        raise LabError("lab_targets_invalid")
    return AttackLab(
        SQLiteNoteWriter(lab_db, policy),
        enabled=True,
        targets=targets,
        policy=policy,
        audit=audit,
        run_active=run_active,
        store=SQLiteRevisionStore(revisions_path(lab_db)),
    )


def _check_marker(database: Path, policy: RolePolicy) -> None:
    try:
        marker = json.loads(marker_path(database).read_text(encoding="utf-8"))
        source = Path(marker["source"])
        version = marker["policy_version"]
    except (OSError, ValueError, KeyError, TypeError):
        raise LabError("lab_db_not_a_copy") from None
    if _same_file(source, database) or version != policy.version:
        raise LabError("lab_db_not_a_copy")


def _same_file(left: Path, right: Path) -> bool:
    left, right = left.expanduser(), right.expanduser()
    if left.exists() and right.exists():
        return os.path.samefile(left, right)
    return os.path.normcase(left.resolve()) == os.path.normcase(right.resolve())


def _file_hash(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1 << 20), b""):
            digest.update(chunk)
    return digest.hexdigest()


def _hash(content: str | None) -> str | None:
    if content is None:
        return None
    return hashlib.sha256(content.encode("utf-8")).hexdigest()


def main(argv: Sequence[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        description=(
            "Attack Lab for the presenter. Commands other than init-copy read the lab from "
            f"{ENABLED_ENV}, {LAB_DB_ENV}, {BUSINESS_DATABASE_ENV} and {TARGETS_ENV}. "
            "The CLI cannot see web runs: only save or restore while no question is running."
        )
    )
    commands = parser.add_subparsers(dest="command", required=True)
    init = commands.add_parser("init-copy", help="create a lab copy of a financial database")
    init.add_argument("--source", required=True, help="reviewed database (never modified)")
    init.add_argument("--output", required=True, help="new lab copy (never overwritten)")
    for name in ("show", "history"):
        commands.add_parser(name).add_argument("target", help="e.g. account.3")
    save = commands.add_parser("save", help="write a payload into a note")
    save.add_argument("target")
    save.add_argument("--expected-revision", type=int, required=True)
    payload = save.add_mutually_exclusive_group(required=True)
    payload.add_argument("--content")
    payload.add_argument("--file", help="UTF-8 file holding the payload")
    restore = commands.add_parser("restore", help="return a note to an earlier revision")
    restore.add_argument("target")
    restore.add_argument("--expected-revision", type=int, required=True)
    restore.add_argument("--to-revision", type=int, default=0)
    args = parser.parse_args(argv)

    try:
        if args.command == "init-copy":
            create_lab_copy(args.source, args.output)
            print("Created Attack Lab copy, marker and revision store.")
            return 0
        lab = _lab_for_cli()
        if args.command == "show":
            print(json.dumps(asyncio.run(lab.get(args.target)), ensure_ascii=False, indent=2))
        elif args.command == "history":
            for revision in lab.history(args.target):
                print(json.dumps(asdict(revision), ensure_ascii=False))
        else:
            user_id = f"cli:{getpass.getuser()}"
            if args.command == "save":
                content = args.content
                if args.file:
                    content = Path(args.file).read_text(encoding="utf-8")
                result = lab.save(
                    args.target,
                    content,
                    expected_revision=args.expected_revision,
                    user_id=user_id,
                )
            else:
                result = lab.restore(
                    args.target,
                    expected_revision=args.expected_revision,
                    user_id=user_id,
                    to_revision=args.to_revision,
                )
            print(json.dumps(asdict(asyncio.run(result)), ensure_ascii=False))
    except LabError as error:
        print(f"Attack Lab refused: {error.category}", file=sys.stderr)
        return 1
    except (OSError, sqlite3.Error):
        print("Attack Lab failed: could not access the lab files.", file=sys.stderr)
        return 1
    return 0


def _lab_for_cli() -> AttackLab:
    from sqlguard.security.audit import JsonlAuditSink

    audit_path = os.environ.get("SQLGUARD_AUDIT_PATH")
    lab = attack_lab_from_env(audit=JsonlAuditSink(audit_path) if audit_path else None)
    if lab is None:
        raise LabError("lab_disabled")
    return lab


if __name__ == "__main__":
    raise SystemExit(main())
