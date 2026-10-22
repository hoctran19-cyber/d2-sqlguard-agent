"""Offline doubles for the security tests.

``GateOnlyExecutor`` is an in-memory SQLite database seeded with the synthetic reference rows
(including canaries) from db/security. Unlike ``sqlguard.security.sqlite.SQLiteExecutor`` it has
no authorizer, so tests using it show what the AST gate alone prevents;
tests/security/test_sqlite_authorizer.py covers the database layer."""

from __future__ import annotations

import sqlite3
from pathlib import Path

import sqlglot

from sqlguard.security.service import ExecutorError, QueryResult

DB_DIR = Path(__file__).resolve().parents[2] / "db" / "security"


class GateOnlyExecutor:
    def __init__(self) -> None:
        self.connection = sqlite3.connect(":memory:")
        for name in ("00_reference_schema.sql", "20_reference_seed.sql"):
            self.connection.executescript((DB_DIR / name).read_text(encoding="utf-8"))
        self.executed: list[str] = []

    async def execute(self, sql, *, role, timeout_seconds, max_rows):
        self.executed.append(sql)
        translated = sqlglot.transpile(sql, read="postgres", write="sqlite")[0]
        try:
            cursor = self.connection.execute(translated)
        except sqlite3.Error:
            raise ExecutorError("db_error") from None
        columns = tuple(description[0] for description in cursor.description or ())
        return QueryResult(columns, tuple(cursor.fetchmany(max_rows + 1)))


class StaticExecutor:
    """Returns fixed rows regardless of SQL; models a compromised or misconfigured database."""

    def __init__(self, columns, rows, error: ExecutorError | None = None) -> None:
        self.result = QueryResult(tuple(columns), tuple(tuple(row) for row in rows))
        self.error = error
        self.calls: list[str] = []

    async def execute(self, sql, *, role, timeout_seconds, max_rows):
        self.calls.append(sql)
        if self.error is not None:
            raise self.error
        return self.result
