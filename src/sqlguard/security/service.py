"""Secure query service: the ``execute_sql`` boundary shared by NL runs and manual SQL.

Pipeline per attempt: argument check -> gate -> execute ``normalized_sql`` with the role's own
DB credential -> row/byte caps -> sanitize -> canary check -> audit -> untrusted envelope.
The role comes from the trusted :class:`SecurityContext` bound at construction; the LLM only
supplies ``sql``.
"""

from __future__ import annotations

import asyncio
import json
from dataclasses import dataclass
from typing import Any, Protocol

from sqlguard.mcp.tools import ToolError
from sqlguard.security.audit import AuditSink
from sqlguard.security.gate import PolicySQLGate, SecurityDecision
from sqlguard.security.policy import RolePolicy
from sqlguard.security.sanitizer import (
    UNTRUSTED_DATA_NOTICE,
    find_canaries,
    json_size,
    sanitize_rows,
)


@dataclass(frozen=True)
class QueryResult:
    columns: tuple[str, ...]
    rows: tuple[tuple[Any, ...], ...]


class ExecutorError(Exception):
    """Database failure mapped to a coarse category; never carries the raw DB message."""

    def __init__(self, category: str, *, retryable: bool = False) -> None:
        super().__init__(category)
        self.category = category
        self.retryable = retryable


class QueryExecutor(Protocol):
    async def execute(
        self, sql: str, *, role: str, timeout_seconds: float, max_rows: int
    ) -> QueryResult: ...


class SecurityToolError(ToolError):
    """Gate denial raised at the tool boundary; carries the safe decision for reflection."""

    def __init__(self, decision: SecurityDecision) -> None:
        super().__init__(decision.reason, category="security_rejection", retryable=False)
        self.decision = decision


class SecureSqlTool:
    """Read-only SQL tool. One instance per run, bound to the run's trusted context."""

    def __init__(
        self,
        gate: PolicySQLGate,
        executor: QueryExecutor,
        *,
        audit: AuditSink | None = None,
        name: str = "query",
    ) -> None:
        self.name = name
        self._gate = gate
        self._executor = executor
        self._audit = audit
        self._attempts = 0
        self.last_decision: SecurityDecision | None = None

    @property
    def input_schema(self) -> dict[str, Any]:
        return {
            "type": "object",
            "required": ["sql"],
            "additionalProperties": False,
            "properties": {
                "sql": {"type": "string", "maxLength": self._gate.policy.limits.max_sql_bytes}
            },
        }

    @property
    def output_schema(self) -> dict[str, Any]:
        return {
            "type": "object",
            "required": ["source", "trust", "columns", "rows", "row_count", "truncated"],
            "properties": {
                "source": {"const": "database"},
                "trust": {"const": "untrusted"},
                "notice": {"type": "string"},
                "columns": {"type": "array", "items": {"type": "string"}},
                "rows": {"type": "array", "items": {"type": "array"}},
                "row_count": {"type": "integer"},
                "truncated": {"type": "boolean"},
                "removed_columns": {"type": "array", "items": {"type": "string"}},
                "decision": {"type": "string"},
                "possible_injection": {"type": "boolean"},
                "executed_sql": {"type": "string"},
                "query_hash": {"type": "string"},
                "policy_version": {"type": "string"},
            },
        }

    async def call(self, arguments: dict[str, Any], *, timeout_seconds: float) -> dict[str, Any]:
        if (
            not isinstance(arguments, dict)
            or set(arguments) != {"sql"}
            or not isinstance(arguments["sql"], str)
        ):
            # A model-supplied "role" or any other extra argument is rejected, not ignored.
            raise ToolError(
                "Only a single 'sql' string argument is accepted",
                category="invalid_tool_input",
                retryable=False,
            )
        self._attempts += 1
        policy = self._gate.policy
        role = self._gate.context.role.casefold()
        decision = self._gate.check(arguments["sql"])
        self.last_decision = decision
        if not decision.allowed:
            self._record(decision, outcome="denied")
            raise SecurityToolError(decision)

        limits = policy.limits
        try:
            result = await self._executor.execute(
                decision.normalized_sql,
                role=role,
                timeout_seconds=min(timeout_seconds, limits.query_timeout_seconds),
                max_rows=limits.max_rows,
            )
        except ExecutorError as error:
            self._record(decision, outcome="db_error", error_category=error.category)
            raise ToolError(
                "Database query failed", category=error.category, retryable=error.retryable
            ) from None
        except (TimeoutError, asyncio.CancelledError):
            self._record(decision, outcome="db_error", error_category="db_timeout", strict=False)
            raise
        except Exception:
            self._record(decision, outcome="db_error", error_category="db_error")
            raise ToolError("Database query failed", category="db_error", retryable=False) from None

        envelope, flags, notices = self._build_envelope(decision, result, policy, role)
        leaked = find_canaries(
            json.dumps(envelope, ensure_ascii=False),
            [canary.value for canary in policy.canaries_for(role)],
        )
        if leaked:
            self._record(decision, outcome="blocked", error_category="canary_leak")
            raise ToolError(
                "Result withheld by output check", category="canary_leak", retryable=False
            )
        self._record(
            decision,
            outcome="executed",
            row_count=envelope["row_count"],
            truncated=envelope["truncated"],
            result_bytes=json_size(envelope),
            injection_flags=flags,
            notices=decision.notices + notices,
        )
        return envelope

    def _build_envelope(self, decision, result: QueryResult, policy: RolePolicy, role: str):
        limits = policy.limits
        rows = list(result.rows[: limits.max_rows])
        truncated = len(result.rows) > limits.max_rows
        sanitized = sanitize_rows(
            result.columns,
            rows,
            max_text_length=limits.max_text_length,
            sensitive_terms=policy.forbidden_column_names(role),
        )
        envelope: dict[str, Any] = {
            "source": "database",
            "trust": "untrusted",
            "notice": UNTRUSTED_DATA_NOTICE,
            "columns": list(sanitized.columns),
            "rows": [list(row) for row in sanitized.rows],
            "row_count": len(sanitized.rows),
            "truncated": truncated,
            "removed_columns": list(decision.removed_columns),
            "decision": str(decision.kind),
            "possible_injection": bool(sanitized.flags),
            "executed_sql": decision.normalized_sql,
            "query_hash": decision.query_hash,
            "policy_version": policy.version,
        }
        while envelope["rows"] and json_size(envelope) > limits.max_result_bytes:
            envelope["rows"].pop()
            envelope["truncated"] = True
        envelope["row_count"] = len(envelope["rows"])
        notices: tuple[str, ...] = ()
        if envelope["truncated"]:
            notices += ("rows_truncated",)
        if sanitized.truncated_values:
            notices += ("values_truncated",)
        if sanitized.flags:
            notices += ("possible_injection",)
        return envelope, len(sanitized.flags), notices

    def _record(self, decision: SecurityDecision, *, outcome: str, strict: bool = True, **extra):
        if self._audit is None:
            return
        try:
            self._audit.record(
                self._gate.audit_record(
                    decision, phase="execute", attempt=self._attempts, outcome=outcome, **extra
                )
            )
        except Exception:
            if strict:
                # No audit, no result: fail closed.
                raise ToolError(
                    "Audit write failed", category="audit_error", retryable=False
                ) from None


def find_leaks(text: str, policy: RolePolicy, role: str) -> tuple[str, ...]:
    """Output check for a final answer or event payload: canaries the role must never see."""
    return find_canaries(text, [canary.value for canary in policy.canaries_for(role)])
