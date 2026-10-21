"""Read-only SQLite executor for the secure query service."""

from __future__ import annotations

import asyncio
import sqlite3
import time
from pathlib import Path

from sqlguard.security.service import ExecutorError, QueryResult


class SQLiteExecutor:
    """Execute one gate-normalized statement against an existing read-only SQLite file."""

    def __init__(self, path: str | Path) -> None:
        database = Path(path).expanduser()
        if not database.is_file():
            raise ExecutorError("db_unavailable")
        self._uri = f"{database.resolve().as_uri()}?mode=ro"

    async def execute(
        self, sql: str, *, role: str, timeout_seconds: float, max_rows: int
    ) -> QueryResult:
        del role
        return await asyncio.to_thread(self._run, sql, timeout_seconds, max_rows)

    def _run(self, sql: str, timeout_seconds: float, max_rows: int) -> QueryResult:
        deadline = time.monotonic() + timeout_seconds
        try:
            with sqlite3.connect(self._uri, uri=True, timeout=timeout_seconds) as connection:
                connection.execute("PRAGMA query_only = ON")
                connection.set_progress_handler(lambda: time.monotonic() >= deadline, 1000)
                cursor = connection.execute(sql)
                columns = tuple(column[0] for column in cursor.description or ())
                rows = tuple(cursor.fetchmany(max_rows + 1))
                connection.set_progress_handler(None, 0)
        except sqlite3.OperationalError as error:
            message = str(error).casefold()
            if "interrupted" in message and time.monotonic() >= deadline:
                raise ExecutorError("db_timeout") from None
            if "readonly" in message:
                raise ExecutorError("db_read_only_violation") from None
            if any(
                term in message for term in ("no such table", "no such column", "no such function")
            ):
                raise ExecutorError("db_schema_error") from None
            if "syntax error" in message:
                raise ExecutorError("db_syntax_error") from None
            raise ExecutorError("db_error") from None
        except sqlite3.ProgrammingError:
            raise ExecutorError("db_syntax_error") from None
        except sqlite3.DatabaseError:
            raise ExecutorError("db_error") from None
        if time.monotonic() >= deadline:
            raise ExecutorError("db_timeout")
        return QueryResult(columns=columns, rows=rows)
