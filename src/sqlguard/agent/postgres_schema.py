"""Role-filtered PostgreSQL schema introspection producing a ``SchemaContext``.

Only table names, column names and data types are read from ``information_schema``. The
role policy decides which tables and columns may be exposed: its allow-list is sent as query
parameters (identifiers are never interpolated into SQL) and applied again to the rows that
come back, so forbidden tables or columns never reach the planner even if the database
reports them. Each call uses the role's own runtime DSN (``SQLGUARD_DB_DSN_<ROLE>``) in a
READ ONLY transaction with a bounded connect and statement timeout. Raw database messages and
DSNs are never propagated; failures map to coarse ``SchemaAdapterError`` categories.
"""

from __future__ import annotations

import asyncio
import os
from collections.abc import Callable, Iterable, Mapping
from contextlib import AbstractContextManager
from typing import Any

from sqlguard.agent.schema import SchemaColumn, SchemaContext, SchemaTable
from sqlguard.security.policy import RolePolicy, load_default_policy
from sqlguard.security.postgres import DSN_ENV_PREFIX

_COLUMNS_SQL = (
    "SELECT table_name, column_name, data_type, udt_name, ordinal_position "
    "FROM information_schema.columns "
    "WHERE table_schema = %s AND table_name = ANY(%s) "
    "ORDER BY table_name, ordinal_position, column_name"
)
_SQLSTATE_QUERY_CANCELED = "57014"
_PERMISSION_SQLSTATES = ("42501", "28000", "28P01")

Connector = Callable[[str, int], AbstractContextManager[Any]]


class SchemaAdapterError(Exception):
    """Safe, coarse failure; ``category`` is the only detail callers should rely on."""

    def __init__(self, category: str, *, retryable: bool = False) -> None:
        super().__init__(category)
        self.category = category
        self.retryable = retryable


def _default_connector(dsn: str, connect_timeout: int) -> AbstractContextManager[Any]:
    try:
        import psycopg
    except ImportError:
        raise SchemaAdapterError("schema_driver_missing") from None
    return psycopg.connect(dsn, connect_timeout=connect_timeout)


class PostgresSchemaAdapter:
    def __init__(
        self,
        dsn_by_role: Mapping[str, str],
        policy: RolePolicy | None = None,
        *,
        schema: str | None = None,
        connect_timeout_seconds: int = 5,
        statement_timeout_seconds: float = 3.0,
        connector: Connector | None = None,
    ) -> None:
        if not isinstance(connect_timeout_seconds, int) or connect_timeout_seconds <= 0:
            raise SchemaAdapterError("schema_invalid_config")
        if not statement_timeout_seconds > 0:
            raise SchemaAdapterError("schema_invalid_config")
        self._policy = policy or load_default_policy()
        self._schema = (schema or self._policy.schema).casefold()
        if not self._schema.strip():
            raise SchemaAdapterError("schema_invalid_config")
        self._dsns = {role.casefold(): dsn for role, dsn in dsn_by_role.items() if dsn}
        self._connect_timeout = connect_timeout_seconds
        self._statement_timeout_ms = max(1, int(statement_timeout_seconds * 1000))
        self._connector = connector or _default_connector

    @classmethod
    def from_env(
        cls,
        policy: RolePolicy | None = None,
        *,
        env: Mapping[str, str] | None = None,
        **options: Any,
    ) -> PostgresSchemaAdapter:
        """Read ``SQLGUARD_DB_DSN_<ROLE>`` for every role in the policy."""
        env = os.environ if env is None else env
        policy = policy or load_default_policy()
        dsns = {
            role: env[DSN_ENV_PREFIX + role.upper()]
            for role in policy.roles
            if env.get(DSN_ENV_PREFIX + role.upper())
        }
        return cls(dsns, policy, **options)

    async def load(self, role: str, tables: Iterable[str] | None = None) -> SchemaContext:
        return await asyncio.to_thread(self.load_sync, role, tables)

    def load_sync(self, role: str, tables: Iterable[str] | None = None) -> SchemaContext:
        if not isinstance(role, str) or not self._policy.has_role(role):
            raise SchemaAdapterError("schema_unknown_role")
        selected = self._select_tables(role, tables)
        dsn = self._dsns.get(role.casefold())
        if dsn is None:
            raise SchemaAdapterError("schema_role_unconfigured")
        rows = self._fetch(dsn, selected)
        return self._build(role, selected, rows)

    def _select_tables(self, role: str, requested: Iterable[str] | None) -> tuple[str, ...]:
        allowed = self._policy.allowed_tables(role)
        if requested is None:
            return tuple(sorted(allowed))
        if isinstance(requested, str):
            raise SchemaAdapterError("schema_invalid_config")
        wanted = {name.casefold() for name in requested if isinstance(name, str)}
        # An unknown or forbidden table is rejected without saying which one it was.
        if not wanted or not wanted <= allowed:
            raise SchemaAdapterError("schema_table_not_allowed")
        return tuple(sorted(wanted))

    def _fetch(self, dsn: str, tables: tuple[str, ...]) -> list[tuple[Any, ...]]:
        try:
            with self._connector(dsn, self._connect_timeout) as conn:
                conn.read_only = True
                with conn.cursor() as cursor:
                    cursor.execute(
                        "SELECT set_config('statement_timeout', %s, true)",
                        (f"{self._statement_timeout_ms}ms",),
                    )
                    cursor.execute(_COLUMNS_SQL, (self._schema, list(tables)))
                    rows = [tuple(row) for row in cursor.fetchall()]
                conn.rollback()
        except SchemaAdapterError:
            raise
        except Exception as error:
            raise _classify(error) from None
        return rows

    def _build(
        self, role: str, selected: tuple[str, ...], rows: list[tuple[Any, ...]]
    ) -> SchemaContext:
        permitted = set(selected)
        collected: dict[str, dict[str, tuple[int, str]]] = {}
        try:
            for table, column, data_type, udt_name, position in rows:
                table_key, column_key = str(table), str(column)
                # Policy identifiers are lower-case; a quoted mixed-case catalog name is a
                # different object and must not inherit the allowed identifier's permissions.
                if table_key not in permitted or not self._policy.can_read(
                    role, table_key, column_key
                ):
                    continue
                if column_key != column_key.casefold():
                    continue
                kind = str(udt_name if data_type == "USER-DEFINED" else data_type)
                collected.setdefault(table_key, {})[column_key] = (int(position), kind)
            tables = tuple(
                SchemaTable(
                    name=table,
                    columns=tuple(
                        SchemaColumn(name=column, data_type=kind)
                        for column, (_, kind) in sorted(
                            collected[table].items(), key=lambda item: (item[1][0], item[0])
                        )
                    ),
                )
                for table in sorted(collected)
            )
            if not tables:
                raise SchemaAdapterError("schema_empty")
            return SchemaContext(tables=tables, dialect="postgres")
        except SchemaAdapterError:
            raise
        except (TypeError, ValueError):
            raise SchemaAdapterError("schema_invalid_metadata") from None


def _classify(error: Exception) -> SchemaAdapterError:
    sqlstate = str(getattr(error, "sqlstate", "") or "")
    if isinstance(error, TimeoutError) or sqlstate == _SQLSTATE_QUERY_CANCELED:
        return SchemaAdapterError("schema_timeout", retryable=True)
    if sqlstate in _PERMISSION_SQLSTATES:
        return SchemaAdapterError("schema_permission_denied")
    if isinstance(error, OSError) or sqlstate.startswith("08") or _is_operational(error):
        return SchemaAdapterError("schema_unavailable", retryable=True)
    return SchemaAdapterError("schema_error")


def _is_operational(error: Exception) -> bool:
    return any(cls.__name__ == "OperationalError" for cls in type(error).__mro__)
