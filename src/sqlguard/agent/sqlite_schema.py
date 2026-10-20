"""Load SQLite schema metadata filtered by the trusted SQLGuard role policy."""

from __future__ import annotations

import asyncio
import os
import sqlite3
from collections.abc import Iterable, Mapping
from pathlib import Path

from sqlguard.agent.postgres_schema import SchemaAdapterError
from sqlguard.agent.schema import SchemaColumn, SchemaContext, SchemaTable
from sqlguard.security.policy import RolePolicy, load_default_policy

SQLITE_PATH_ENV = "SQLGUARD_SQLITE_PATH"


class SQLiteSchemaAdapter:
    def __init__(
        self,
        path: str | Path,
        policy: RolePolicy | None = None,
    ) -> None:
        database = Path(path).expanduser()
        if not database.is_file():
            raise SchemaAdapterError("schema_sqlite_db_missing")
        self._uri = f"{database.resolve().as_uri()}?mode=ro"
        self._policy = policy or load_default_policy()

    @classmethod
    def from_env(
        cls,
        policy: RolePolicy | None = None,
        *,
        env: Mapping[str, str] | None = None,
    ) -> SQLiteSchemaAdapter:
        env = os.environ if env is None else env
        path = env.get(SQLITE_PATH_ENV)
        if not path or not path.strip():
            raise SchemaAdapterError("schema_sqlite_path_missing")
        try:
            return cls(path, policy)
        except SchemaAdapterError:
            raise
        except OSError:
            raise SchemaAdapterError("schema_sqlite_db_unavailable") from None

    async def load(self, role: str, tables: Iterable[str] | None = None) -> SchemaContext:
        return await asyncio.to_thread(self.load_sync, role, tables)

    def load_sync(self, role: str, tables: Iterable[str] | None = None) -> SchemaContext:
        if not isinstance(role, str) or not self._policy.has_role(role):
            raise SchemaAdapterError("schema_unknown_role")
        selected = self._select_tables(role, tables)
        try:
            with sqlite3.connect(self._uri, uri=True, timeout=5) as connection:
                connection.execute("PRAGMA query_only = ON")
                available = {
                    row[0]
                    for row in connection.execute(
                        "SELECT name FROM sqlite_master "
                        "WHERE type = 'table' AND name NOT LIKE 'sqlite_%'"
                    )
                }
                schema_tables = []
                for table in selected:
                    if table not in available:
                        continue
                    quoted_table = '"' + table.replace('"', '""') + '"'
                    columns = []
                    for row in connection.execute(f"PRAGMA table_info({quoted_table})"):
                        name, declared_type = row[1], row[2]
                        if name == name.casefold() and self._policy.can_read(role, table, name):
                            columns.append(
                                SchemaColumn(name=name, data_type=declared_type or "unknown")
                            )
                    if columns:
                        schema_tables.append(SchemaTable(table, tuple(columns)))
        except sqlite3.Error:
            raise SchemaAdapterError("schema_sqlite_error") from None
        if not schema_tables:
            raise SchemaAdapterError("schema_empty")
        return SchemaContext(tables=tuple(schema_tables), dialect="sqlite")

    def _select_tables(self, role: str, requested: Iterable[str] | None) -> tuple[str, ...]:
        allowed = self._policy.allowed_tables(role)
        if requested is None:
            return tuple(sorted(allowed))
        if isinstance(requested, str):
            raise SchemaAdapterError("schema_invalid_config")
        wanted = {name.casefold() for name in requested if isinstance(name, str)}
        if not wanted or not wanted <= allowed:
            raise SchemaAdapterError("schema_table_not_allowed")
        return tuple(sorted(wanted))
