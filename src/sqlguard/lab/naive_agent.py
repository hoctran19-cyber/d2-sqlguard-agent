"""The naive agent: a model-driven tool loop with no gate and no role authorizer (N2, N4).

``NaiveSqliteExecutor`` runs whatever SELECT the model writes on the Attack Lab copy, read-only
and bounded, but with every column readable. ``NaiveAgent`` lets the model call it up to
``max_tool_calls`` times, hands it the rows verbatim and returns the model's own answer. Both
choices are the weaknesses the demo shows; see ``docs/threat-model/NAIVE_AGENT_DEMO.md``.
"""

from __future__ import annotations

import asyncio
import sqlite3
import time
from contextlib import closing
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from sqlguard.lab.model import (
    ModelReply,
    NaiveModelError,
    ToolCallingModel,
    ToolResult,
    ToolResults,
    Turn,
    UserTurn,
)
from sqlguard.lab.naive_guard import ensure_lab_copy
from sqlguard.lab.naive_prompt import build_naive_system_prompt
from sqlguard.security.policy import RolePolicy

MAX_TOOL_CALLS = 3
MAX_ROWS = 100
TIMEOUT_SECONDS = 3.0
MAX_ERROR_LENGTH = 300


@dataclass(frozen=True)
class NaiveStep:
    """One ``execute_sql`` call: the model's SQL and what came back."""

    sql: str
    columns: tuple[str, ...] = ()
    rows: tuple[tuple[Any, ...], ...] = ()
    truncated: bool = False
    error: str | None = None

    def model_payload(self) -> dict[str, Any]:
        """What the model reads: the raw rows (or the raw error), with no fence and no label."""
        if self.error is not None:
            return {"error": self.error}
        return {
            "columns": list(self.columns),
            "rows": [list(row) for row in self.rows],
            "row_count": len(self.rows),
            "truncated": self.truncated,
        }


@dataclass(frozen=True)
class NaiveResult:
    status: str  # completed | blocked | failed
    answer_markdown: str
    steps: tuple[NaiveStep, ...]
    model: str
    model_calls: int
    error_category: str | None = None

    def to_payload(self) -> dict[str, Any]:
        return {
            "status": self.status,
            "answer_markdown": self.answer_markdown,
            "steps": [
                {
                    "sql": step.sql,
                    "columns": list(step.columns),
                    "rows": [list(row) for row in step.rows],
                    "truncated": step.truncated,
                    "error": step.error,
                }
                for step in self.steps
            ],
            "tool_calls": len(self.steps),
            "model": self.model,
            "model_calls": self.model_calls,
            "error_category": self.error_category,
        }


def _cell(value: Any) -> Any:
    return value.hex() if isinstance(value, bytes) else value


_SANDBOX_DENIED = frozenset({sqlite3.SQLITE_ATTACH, sqlite3.SQLITE_DETACH, sqlite3.SQLITE_PRAGMA})


def _sandbox_authorizer(action: int, *args: Any) -> int:
    """Not a role check: every table and column stays readable.

    It only keeps the query inside the lab copy (no ``ATTACH`` of another file) and stops
    ``PRAGMA`` from undoing ``query_only``.
    """
    return sqlite3.SQLITE_DENY if action in _SANDBOX_DENIED else sqlite3.SQLITE_OK


class NaiveSqliteExecutor:
    """Read-only SQLite on the lab copy: ``mode=ro``, ``query_only``, timeout, row cap.

    No role authorizer and no gate: any column of any table can be read. The lab-copy check runs
    again before every query, and ``ATTACH`` is refused, so nothing but the lab copy is opened.
    """

    def __init__(
        self,
        database: str | Path,
        policy: RolePolicy,
        *,
        timeout_seconds: float = TIMEOUT_SECONDS,
        max_rows: int = MAX_ROWS,
    ) -> None:
        self._policy = policy
        self._database = ensure_lab_copy(database, policy)
        self._timeout = timeout_seconds
        self._max_rows = max_rows

    def execute(self, sql: str) -> NaiveStep:
        database = ensure_lab_copy(self._database, self._policy)
        deadline = time.monotonic() + self._timeout
        try:
            connection = sqlite3.connect(f"{database.resolve().as_uri()}?mode=ro", uri=True)
            with closing(connection):
                connection.execute("PRAGMA query_only = ON")
                # Installed after the PRAGMA above, which it would deny.
                connection.set_authorizer(_sandbox_authorizer)
                connection.set_progress_handler(lambda: time.monotonic() >= deadline, 1000)
                cursor = connection.execute(sql)
                columns = tuple(column[0] for column in cursor.description or ())
                rows = cursor.fetchmany(self._max_rows + 1)
        except sqlite3.Error as error:
            message = (
                "timeout"
                if time.monotonic() >= deadline
                else f"{type(error).__name__}: {error}"[:MAX_ERROR_LENGTH]
            )
            return NaiveStep(sql=sql, error=message)
        return NaiveStep(
            sql=sql,
            columns=columns,
            rows=tuple(tuple(_cell(v) for v in row) for row in rows[: self._max_rows]),
            truncated=len(rows) > self._max_rows,
        )


class NaiveAgent:
    """Question in, model-written answer out; the model decides every query."""

    def __init__(
        self,
        model: ToolCallingModel,
        executor: NaiveSqliteExecutor,
        policy: RolePolicy,
        *,
        max_tool_calls: int = MAX_TOOL_CALLS,
    ) -> None:
        if max_tool_calls < 1:
            raise ValueError("max_tool_calls must be at least 1")
        self._model = model
        self._executor = executor
        self._policy = policy
        self._max_tool_calls = max_tool_calls

    async def run(self, question: str, role: str) -> NaiveResult:
        system = build_naive_system_prompt(self._policy, role)
        turns: list[Turn] = [UserTurn(question)]
        steps: list[NaiveStep] = []
        calls = 0
        # Each round either answers or runs at least one query, and the last allowed round has
        # tools switched off, so the loop ends; the cap is a second fuse.
        for _ in range(self._max_tool_calls + 2):
            allow_tools = len(steps) < self._max_tool_calls
            try:
                reply: ModelReply = await self._model.generate(
                    system, turns, allow_tools=allow_tools
                )
            except NaiveModelError as error:
                status = "blocked" if error.category == "blocked" else "failed"
                return self._result(status, "", steps, calls, error.category)
            calls += 1
            turns.append(reply)
            if not reply.tool_calls or not allow_tools:
                return self._result("completed", reply.text, steps, calls)
            results = []
            for call in reply.tool_calls:
                if len(steps) >= self._max_tool_calls:
                    results.append(ToolResult(call, {"error": "tool call budget exhausted"}))
                    continue
                step = await asyncio.to_thread(self._executor.execute, call.sql)
                steps.append(step)
                results.append(ToolResult(call, step.model_payload()))
            turns.append(ToolResults(tuple(results)))
        return self._result("failed", "", steps, calls, "loop_limit")

    def _result(
        self,
        status: str,
        answer: str,
        steps: list[NaiveStep],
        calls: int,
        error_category: str | None = None,
    ) -> NaiveResult:
        return NaiveResult(
            status=status,
            answer_markdown=answer,
            steps=tuple(steps),
            model=self._model.name,
            model_calls=calls,
            error_category=error_category,
        )
