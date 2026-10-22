"""Read-only SQLite executor for the secure query service.

SQLite has no roles or grants, so the database-side boundary (independent of the AST gate) is an
authorizer installed on every connection and built from the same ``RolePolicy`` as the gate, for
the trusted role of the call. It allows a SELECT, reads of the (table, column) pairs that role may
read in ``main``, and SQLite functions mapped from the policy allowlist; every other action
(PRAGMA, ATTACH, writes, DDL, temp objects, recursive CTEs, ``sqlite_master``) is denied. The file
is also opened ``mode=ro`` with ``PRAGMA query_only``. Denials use ``SQLITE_DENY``, never
``SQLITE_IGNORE``, which would silently turn a forbidden column into ``NULL``.

SQLite never calls the authorizer for the columns a ``JOIN ... USING`` or ``NATURAL JOIN`` compares
(nor, with ``COUNT(*)``, for the table itself), so such a join could test any column value, even
of a table outside the policy. The gate already rejects both; the executor refuses them as well.
"""

from __future__ import annotations

import asyncio
import sqlite3
import time
from collections.abc import Callable
from contextlib import closing
from pathlib import Path

from sqlguard.security.policy import RolePolicy
from sqlguard.security.service import ExecutorError, QueryResult

# SQLite function names that SQLGlot's sqlite dialect emits for each function class the policy can
# allow. A policy function missing here has no SQLite name and stays denied by the database.
_SQLITE_FUNCTIONS: dict[str, tuple[str, ...]] = {
    "Count": ("count",),
    "Sum": ("sum",),
    "Avg": ("avg",),
    "Min": ("min",),
    "Max": ("max",),
    "Round": ("round",),
    "Coalesce": ("coalesce",),
    "Nullif": ("nullif",),
    "Lower": ("lower",),
    "Upper": ("upper",),
    "Abs": ("abs",),
    "Length": ("length",),
    "Substring": ("substr", "substring"),
    "CurrentDate": ("current_date",),
    "CurrentTimestamp": ("current_timestamp",),
    "StrToTime": ("strftime",),
    "TimeToStr": ("strftime",),
}
# Functions SQLite runs for syntax the gate treats as structural: LIKE, ILIKE (LOWER .. LIKE
# LOWER ..), IIF (exp.If) and CAST to DATE/TIMESTAMP (DATE(), DATETIME()).
_STRUCTURAL_FUNCTIONS = frozenset({"like", "lower", "iif", "date", "datetime"})
# Join keywords whose compared columns the authorizer never sees (see the module docstring).
_UNCHECKED_JOIN_KEYWORDS = frozenset({"NATURAL", "USING"})

Authorizer = Callable[[int, str | None, str | None, str | None, str | None], int]


def _is_id_char(char: str) -> bool:
    # SQLite's IdChar(): ASCII letters, digits, "_", "$", and every non-ASCII character.
    return (char.isascii() and (char.isalnum() or char in "_$")) or ord(char) >= 0x80


def _skip_quoted(sql: str, start: int, quote: str) -> int:
    """Index just past a quoted token opened before ``start``; a doubled quote is an escape."""
    while True:
        end = sql.find(quote, start)
        if end < 0:
            return len(sql)
        if not sql.startswith(quote * 2, end):
            return end + 1
        start = end + 2


def has_unchecked_join(sql: str) -> bool:
    """True if ``NATURAL`` or ``USING`` appears as a keyword, following SQLite's own lexical rules.

    String literals, identifiers quoted with double quotes, backticks or brackets, and comments
    (``--`` to end of line, non-nested ``/* … */``) are skipped exactly as SQLite's tokenizer
    skips them, so the keywords cannot be hidden from this scan while SQLite still parses them.
    A bare word that merely looks like a keyword is refused too, which only errs on the side of
    denying.
    """
    index, length = 0, len(sql)
    while index < length:
        char = sql[index]
        if sql.startswith("--", index):
            end = sql.find("\n", index)
            index = length if end < 0 else end + 1
        elif sql.startswith("/*", index):
            end = sql.find("*/", index + 2)
            index = length if end < 0 else end + 2
        elif char in "'\"`":
            index = _skip_quoted(sql, index + 1, char)
        elif char == "[":
            end = sql.find("]", index + 1)
            index = length if end < 0 else end + 1
        elif _is_id_char(char):
            start = index
            while index < length and _is_id_char(sql[index]):
                index += 1
            word = sql[start:index]
            if word.isascii() and word.upper() in _UNCHECKED_JOIN_KEYWORDS:
                return True
        else:
            index += 1
    return False


def build_authorizer(policy: RolePolicy, role: str) -> Authorizer:
    """Authorizer callback for one trusted role; anything not explicitly allowed is denied."""
    readable = {table: policy.allowed_columns(role, table) for table in policy.allowed_tables(role)}
    functions = _STRUCTURAL_FUNCTIONS | {
        name for function in policy.functions for name in _SQLITE_FUNCTIONS.get(function, ())
    }

    def authorize(
        action: int,
        arg1: str | None,
        arg2: str | None,
        database: str | None,
        source: str | None,
    ) -> int:
        if action == sqlite3.SQLITE_SELECT:
            return sqlite3.SQLITE_OK
        if action == sqlite3.SQLITE_READ:
            columns = readable.get((arg1 or "").casefold())
            if columns is not None:
                # A table used without reading a column (e.g. COUNT(*)) is reported with an
                # empty column and no database name; it only needs the table to be readable.
                if not arg2 or (database == "main" and arg2.casefold() in columns):
                    return sqlite3.SQLITE_OK
            return sqlite3.SQLITE_DENY
        if action == sqlite3.SQLITE_FUNCTION and (arg2 or "").casefold() in functions:
            return sqlite3.SQLITE_OK
        return sqlite3.SQLITE_DENY

    return authorize


class SQLiteExecutor:
    """Execute one gate-normalized statement against an existing read-only SQLite file."""

    def __init__(self, path: str | Path, policy: RolePolicy) -> None:
        # No default policy: the authorizer must use the exact policy the gate checks against.
        database = Path(path).expanduser()
        if not database.is_file():
            raise ExecutorError("db_unavailable")
        self._uri = f"{database.resolve().as_uri()}?mode=ro"
        self._policy = policy

    async def execute(
        self, sql: str, *, role: str, timeout_seconds: float, max_rows: int
    ) -> QueryResult:
        if not self._policy.has_role(role):
            raise ExecutorError("db_role_unconfigured")
        if has_unchecked_join(sql):
            raise ExecutorError("db_permission_denied")
        authorizer = build_authorizer(self._policy, role)
        return await asyncio.to_thread(self._run, sql, authorizer, timeout_seconds, max_rows)

    def _run(
        self, sql: str, authorizer: Authorizer, timeout_seconds: float, max_rows: int
    ) -> QueryResult:
        deadline = time.monotonic() + timeout_seconds
        try:
            connection = sqlite3.connect(self._uri, uri=True, timeout=timeout_seconds)
            with closing(connection):
                connection.execute("PRAGMA query_only = ON")
                # Installed after the PRAGMA above, which the authorizer would deny.
                connection.set_authorizer(authorizer)
                connection.set_progress_handler(lambda: time.monotonic() >= deadline, 1000)
                cursor = connection.execute(sql)
                columns = tuple(column[0] for column in cursor.description or ())
                rows = tuple(cursor.fetchmany(max_rows + 1))
                connection.set_progress_handler(None, 0)
        except sqlite3.DatabaseError as error:
            # Checked first: an authorizer denial has code SQLITE_AUTH, except a denied function,
            # which SQLite reports as SQLITE_ERROR "not authorized to use function: <name>".
            message = str(error).casefold()
            if getattr(
                error, "sqlite_errorcode", None
            ) == sqlite3.SQLITE_AUTH or message.startswith("not authorized to use function"):
                raise ExecutorError("db_permission_denied") from None
            if isinstance(error, sqlite3.ProgrammingError):
                raise ExecutorError("db_syntax_error") from None
            if not isinstance(error, sqlite3.OperationalError):
                raise ExecutorError("db_error") from None
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
        if time.monotonic() >= deadline:
            raise ExecutorError("db_timeout")
        return QueryResult(columns=columns, rows=rows)
