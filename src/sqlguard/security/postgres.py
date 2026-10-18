"""PostgreSQL executor for the secure query service (optional ``postgres`` extra).

Each call opens a connection with the *role's own* runtime credential, runs one READ ONLY
transaction with a local statement timeout, executes a single prepared statement, fetches at
most ``max_rows + 1`` rows to detect truncation, and always rolls back. Database errors are
mapped to coarse categories; raw messages (which can echo data or schema details) are never
propagated.
"""

from __future__ import annotations

import asyncio
import os
from collections.abc import Mapping

from sqlguard.security.service import ExecutorError, QueryResult

DSN_ENV_PREFIX = "SQLGUARD_DB_DSN_"


class PostgresExecutor:
    def __init__(self, dsn_by_role: Mapping[str, str], *, connect_timeout_seconds: int = 5) -> None:
        self._dsns = {role.casefold(): dsn for role, dsn in dsn_by_role.items()}
        self._connect_timeout = connect_timeout_seconds

    @classmethod
    def from_env(cls, roles: tuple[str, ...] = ("sales", "finance", "operations")):
        """Read ``SQLGUARD_DB_DSN_<ROLE>`` variables; credentials never live in code."""
        dsns = {
            role: os.environ[DSN_ENV_PREFIX + role.upper()]
            for role in roles
            if os.environ.get(DSN_ENV_PREFIX + role.upper())
        }
        return cls(dsns)

    async def execute(
        self, sql: str, *, role: str, timeout_seconds: float, max_rows: int
    ) -> QueryResult:
        dsn = self._dsns.get(role.casefold())
        if dsn is None:
            raise ExecutorError("db_role_unconfigured")
        return await asyncio.to_thread(self._run, dsn, sql, timeout_seconds, max_rows)

    def _run(self, dsn: str, sql: str, timeout_seconds: float, max_rows: int) -> QueryResult:
        import psycopg
        from psycopg import errors

        timeout_ms = max(1, int(timeout_seconds * 1000))
        try:
            with psycopg.connect(dsn, connect_timeout=self._connect_timeout) as conn:
                conn.read_only = True
                with conn.cursor() as cursor:
                    cursor.execute(
                        "SELECT set_config('statement_timeout', %s, true)", (f"{timeout_ms}ms",)
                    )
                    # Without parameters psycopg uses the simple protocol, which runs every
                    # statement in a "a; b" string. prepare=True forces Parse (extended
                    # protocol), so the server rejects multiple statements.
                    cursor.execute(sql, prepare=True)  # type: ignore[arg-type]
                    columns = tuple(column.name for column in cursor.description or ())
                    rows = tuple(tuple(row) for row in cursor.fetchmany(max_rows + 1))
                conn.rollback()
        except errors.QueryCanceled:
            raise ExecutorError("db_timeout") from None
        except errors.InsufficientPrivilege:
            raise ExecutorError("db_permission_denied") from None
        except errors.ReadOnlySqlTransaction:
            raise ExecutorError("db_read_only_violation") from None
        except (errors.UndefinedColumn, errors.UndefinedTable, errors.UndefinedFunction):
            raise ExecutorError("db_schema_error") from None
        except errors.SyntaxError:
            raise ExecutorError("db_syntax_error") from None
        except psycopg.OperationalError:
            raise ExecutorError("db_unavailable", retryable=True) from None
        except psycopg.Error:
            raise ExecutorError("db_error") from None
        return QueryResult(columns=columns, rows=rows)
