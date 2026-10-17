from __future__ import annotations

import asyncio
from datetime import UTC, datetime
from time import perf_counter
from typing import Any

from sqlguard.agent.models import (
    AgentRequest,
    AgentResult,
    AgentState,
    ExecutionBudget,
    RunStatus,
)
from sqlguard.agent.planning import Planner
from sqlguard.mcp.tools import ToolError, ToolRegistry
from sqlguard.memory.store import MemoryStore
from sqlguard.observability.events import Event, EventSink
from sqlguard.security.gate import SecurityGate


class AgentController:
    def __init__(
        self,
        planner: Planner,
        tools: ToolRegistry,
        security_gate: SecurityGate,
        memory: MemoryStore,
        events: EventSink,
        budget: ExecutionBudget | None = None,
    ) -> None:
        self._planner = planner
        self._tools = tools
        self._security_gate = security_gate
        self._memory = memory
        self._events = events
        self._budget = budget or ExecutionBudget()

    async def run(self, request: AgentRequest) -> AgentResult:
        state = AgentState(request=request)
        started_at = perf_counter()
        deadline = asyncio.get_running_loop().time() + self._budget.run_timeout_seconds
        try:
            self._emit(state, "run_started")
            if not request.question.strip():
                raise ValueError("Question must not be empty")
            await asyncio.wait_for(
                self._execute(state, deadline), timeout=self._budget.run_timeout_seconds
            )
        except TimeoutError:
            state.status = RunStatus.TIMED_OUT
            state.failure_reason = "run_timeout"
            state.errors.append(state.failure_reason)
        except _BudgetExceeded as error:
            state.status = RunStatus.BUDGET_EXHAUSTED
            state.failure_reason = str(error)
            state.errors.append(state.failure_reason)
        except _SecurityRejected:
            state.status = RunStatus.REFUSED
            state.failure_reason = "security_rejection"
            state.errors.append(state.failure_reason)
        except _EventSinkFailure:
            state.status = RunStatus.FAILED
            state.failure_reason = "event_sink_error"
            state.errors.append(state.failure_reason)
        except _MemoryFailure:
            state.status = RunStatus.FAILED
            state.failure_reason = "memory_error"
            state.errors.append(state.failure_reason)
        except _SecurityGateFailure:
            state.status = RunStatus.FAILED
            state.failure_reason = "security_gate_error"
            state.errors.append(state.failure_reason)
        except _PlannerFailure:
            state.status = RunStatus.FAILED
            state.failure_reason = "planner_error"
            state.errors.append(state.failure_reason)
        except Exception as error:
            state.status = RunStatus.FAILED
            state.failure_reason = _error_category(error)
            state.errors.append(_error_category(error))
        except asyncio.CancelledError:
            state.status = RunStatus.FAILED
            state.failure_reason = "cancelled"
            state.errors.append(state.failure_reason)
            raise
        finally:
            state.finished_at = datetime.now(UTC)
            self._set_terminal_step(state)
            try:
                self._memory.append(state.run_id, "state", state.status.value)
            except Exception:
                state.status = RunStatus.FAILED
                state.failure_reason = "memory_error"
                state.errors.append(state.failure_reason)
                self._set_terminal_step(state)
            duration_ms = (perf_counter() - started_at) * 1000
            try:
                self._emit(
                    state,
                    self._terminal_event(state.status),
                    status=state.status.value,
                    error_category=state.failure_reason,
                    duration_ms=duration_ms,
                )
            except _EventSinkFailure:
                state.status = RunStatus.FAILED
                state.failure_reason = "event_sink_error"
                state.errors.append(state.failure_reason)
                self._set_terminal_step(state)
                try:
                    # Correct the stale status written before terminal emission.
                    self._memory.append(state.run_id, "state", state.status.value)
                except Exception:
                    state.errors.append("memory_error")
        return AgentResult(state=state)

    async def _execute(self, state: AgentState, deadline: float) -> None:
        self._ensure_before_deadline(deadline)
        state.current_step = "context_retrieval"
        self._emit(state, "context_retrieval_started")
        try:
            context = self._memory.get(state.run_id)
        except Exception:
            self._emit(
                state,
                "context_retrieval_completed",
                status="failed",
                error_category="memory_error",
            )
            raise _MemoryFailure from None
        self._emit(state, "context_retrieval_completed", status="completed")

        state.current_step = "planning"
        self._ensure_before_deadline(deadline)
        if state.llm_call_count >= self._budget.max_llm_calls:
            raise _BudgetExceeded("planner_call_budget_exhausted")
        self._emit(state, "llm_call_started")
        state.llm_call_count += 1
        planner_started = perf_counter()
        try:
            plan = await self._planner.create_plan(state.request.question, context)
            sql = getattr(plan, "sql", None)
            summary = getattr(plan, "summary", None)
            if not isinstance(sql, str) or not isinstance(summary, str):
                raise TypeError
        except Exception:
            self._emit(
                state,
                "llm_call_completed",
                status="failed",
                error_category="planner_error",
                duration_ms=(perf_counter() - planner_started) * 1000,
            )
            raise _PlannerFailure from None
        self._emit(state, "plan_created")
        self._emit(
            state,
            "llm_call_completed",
            status="completed",
            duration_ms=(perf_counter() - planner_started) * 1000,
        )

        while True:
            self._ensure_before_deadline(deadline)
            state.current_step = "security_check"
            sql_limit = (
                self._budget.max_tool_calls
                if self._budget.max_sql_attempts is None
                else self._budget.max_sql_attempts
            )
            if state.sql_attempt_count >= sql_limit:
                raise _BudgetExceeded("sql_attempt_budget_exhausted")
            self._emit(state, "security_check_started")
            state.sql_attempt_count += 1
            try:
                decision = self._security_gate.check(sql)
                allowed = decision.allowed
                if not isinstance(allowed, bool):
                    raise TypeError
            except Exception:
                self._emit(
                    state,
                    "security_check_completed",
                    status="failed",
                    error_category="security_gate_error",
                )
                raise _SecurityGateFailure from None
            self._emit(
                state,
                "security_check_completed",
                status="allowed" if allowed else "denied",
                error_category=None if allowed else "security_rejection",
            )
            if not allowed:
                raise _SecurityRejected

            state.current_step = "tool_execution"
            if state.tool_call_count >= self._budget.max_tool_calls:
                raise _BudgetExceeded("tool_call_budget_exhausted")
            self._ensure_before_deadline(deadline)
            self._emit(state, "tool_call_started")
            state.tool_call_count += 1
            tool_started = perf_counter()
            try:
                timeout = min(
                    self._budget.query_timeout_seconds,
                    self._remaining_seconds(deadline),
                )
                output = await asyncio.wait_for(
                    self._tools.call(
                        "query",
                        {"sql": sql},
                        timeout_seconds=timeout,
                    ),
                    timeout=timeout,
                )
            except TimeoutError:
                if asyncio.get_running_loop().time() >= deadline:
                    raise TimeoutError
                category = "tool_timeout"
                retryable = True
            except ToolError as error:
                category = error.category
                retryable = error.retryable
            except Exception:
                category = "tool_exception"
                retryable = False
            else:
                self._emit(
                    state,
                    "tool_call_completed",
                    status="completed",
                    duration_ms=(perf_counter() - tool_started) * 1000,
                )
                try:
                    state.final_answer = _format_result(output)
                except Exception:
                    raise _InvalidToolOutput from None
                state.status = RunStatus.SUCCEEDED
                return

            state.errors.append(category)
            self._append_memory(state, "error", category)
            self._emit(
                state,
                "tool_call_completed",
                status="failed",
                error_category=category,
                duration_ms=(perf_counter() - tool_started) * 1000,
            )
            if not retryable:
                raise ToolError(category, category=category) from None
            if state.retry_count >= self._budget.max_retries:
                raise ToolError(category, category=category) from None
            if state.tool_call_count >= self._budget.max_tool_calls:
                raise _BudgetExceeded("tool_call_budget_exhausted")
            if state.sql_attempt_count >= sql_limit:
                raise _BudgetExceeded("sql_attempt_budget_exhausted")
            state.retry_count += 1
            self._append_memory(state, "retry", str(state.retry_count))
            self._emit(state, "retry_started", status="retrying", error_category=category)

    def _emit(self, state: AgentState, event_type: str, **details: Any) -> None:
        try:
            self._events.emit(Event(run_id=state.run_id, event_type=event_type, **details))
        except Exception:
            raise _EventSinkFailure from None

    def _append_memory(self, state: AgentState, kind: str, value: str) -> None:
        try:
            self._memory.append(state.run_id, kind, value)
        except Exception:
            raise _MemoryFailure from None

    @staticmethod
    def _ensure_before_deadline(deadline: float) -> None:
        if asyncio.get_running_loop().time() >= deadline:
            raise TimeoutError

    @staticmethod
    def _remaining_seconds(deadline: float) -> float:
        remaining = deadline - asyncio.get_running_loop().time()
        if remaining <= 0:
            raise TimeoutError
        return remaining

    @staticmethod
    def _set_terminal_step(state: AgentState) -> None:
        terminal_steps = {
            RunStatus.SUCCEEDED: "completed",
            RunStatus.REFUSED: "refused",
            RunStatus.TIMED_OUT: "timed_out",
            RunStatus.BUDGET_EXHAUSTED: "budget_exhausted",
        }
        state.current_step = terminal_steps.get(state.status, "failed")

    @staticmethod
    def _terminal_event(status: RunStatus) -> str:
        terminal_events = {
            RunStatus.SUCCEEDED: "run_completed",
            RunStatus.REFUSED: "run_refused",
            RunStatus.TIMED_OUT: "run_timed_out",
            RunStatus.BUDGET_EXHAUSTED: "budget_exhausted",
            RunStatus.FAILED: "run_failed",
        }
        return terminal_events[status]


class _BudgetExceeded(Exception):
    pass


class _SecurityRejected(Exception):
    pass


class _SecurityGateFailure(Exception):
    pass


class _PlannerFailure(Exception):
    pass


class _MemoryFailure(Exception):
    pass


class _EventSinkFailure(Exception):
    pass


class _InvalidToolOutput(Exception):
    pass


def _format_result(output: Any) -> str:
    if isinstance(output, str):
        return output
    return str(output)


def _error_category(error: Exception) -> str:
    if isinstance(error, _InvalidToolOutput):
        return "invalid_tool_output"
    if isinstance(error, ToolError):
        return error.category
    if isinstance(error, ValueError):
        return "invalid_request"
    return "internal_error"
