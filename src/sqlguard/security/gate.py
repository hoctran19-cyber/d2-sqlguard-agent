from __future__ import annotations

from dataclasses import dataclass
from typing import Protocol

import sqlglot
from sqlglot import exp
from sqlglot.errors import ParseError


@dataclass(frozen=True)
class SecurityDecision:
    allowed: bool
    reason: str
    violations: tuple[str, ...] = ()


class SecurityGate(Protocol):
    def check(self, sql: str) -> SecurityDecision: ...


class ReadOnlySQLGate:
    """Fail-closed, single-SELECT gate; not a complete data authorization policy."""

    def __init__(self, allowed_tables: set[str] | None = None) -> None:
        self._allowed_tables = (
            {table.casefold() for table in allowed_tables} if allowed_tables is not None else None
        )

    def check(self, sql: str) -> SecurityDecision:
        if not sql.strip():
            return _deny("SQL is empty", "empty_sql")
        try:
            statements = sqlglot.parse(sql, read="sqlite")
        except ParseError:
            return _deny("SQL could not be parsed", "parse_error")
        if len(statements) != 1 or statements[0] is None:
            return _deny("Exactly one SQL statement is required", "multiple_statements")
        statement = statements[0]
        if not isinstance(statement, exp.Select):
            return _deny("Only read-only SELECT statements are permitted", "not_select")
        if self._allowed_tables is not None:
            referenced = {
                table.name.casefold() for table in statement.find_all(exp.Table) if table.name
            }
            disallowed = sorted(referenced - self._allowed_tables)
            if disallowed:
                return _deny("Query references a table outside the allowlist", "table_not_allowed")
        return SecurityDecision(allowed=True, reason="Read-only SELECT accepted")


def _deny(reason: str, violation: str) -> SecurityDecision:
    return SecurityDecision(allowed=False, reason=reason, violations=(violation,))
