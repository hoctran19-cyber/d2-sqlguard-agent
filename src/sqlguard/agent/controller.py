from __future__ import annotations

import asyncio
from datetime import UTC, datetime
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
        self._emit(state, "run_started")
        try:
            if not request.question.strip():
                raise ValueError("Question must not be empty")
            await asyncio.wait_for(self._execute(state), timeout=self._budget.run_timeout_seconds)
        except TimeoutError:
            state.status = RunStatus.TIMED_OUT
            state.failure_reason = "Run timed out"
        except _BudgetExceeded as error:
            state.status = RunStatus.BUDGET_EXHAUSTED
            state.failure_reason = str(error)
        except Exception as error:
            state.status = RunStatus.FAILED
            state.failure_reason = _error_category(error)
            state.errors.append(_error_category(error))
        finally:
            state.finished_at = datetime.now(UTC)
            self._memory.append(state.run_id, "state", state.status.value)
            self._emit(
                state,
                "run_completed" if state.status == RunStatus.SUCCEEDED else "run_failed",
                status=state.status.value,
                error_category=state.failure_reason,
            )
        return AgentResult(state=state)

    async def _execute(self, state: AgentState) -> None:
        self._memory.append(state.run_id, "request", state.request.question)
        state.current_step = "context_retrieval"
        context = self._memory.get(state.run_id)
        state.current_step = "planning"
        if state.llm_call_count >= self._budget.max_llm_calls:
            raise _BudgetExceeded("LLM call budget exhausted")
        state.llm_call_count += 1
        self._emit(state, "llm_call_started")
        plan = await self._planner.create_plan(state.request.question, context)
        self._memory.append(state.run_id, "plan", plan.summary)
        self._memory.append(state.run_id, "sql", plan.sql)
        self._emit(state, "plan_created")
        self._emit(state, "llm_call_completed", status="completed")

        state.current_step = "security_check"
        decision = self._security_gate.check(plan.sql)
        self._emit(
            state,
            "security_check_completed",
            status="allowed" if decision.allowed else "denied",
            error_category=None if decision.allowed else "security_rejection",
        )
        if not decision.allowed:
            raise _SecurityRejected(decision.reason)

        state.current_step = "tool_execution"
        while True:
            if state.tool_call_count >= self._budget.max_tool_calls:
                raise _BudgetExceeded("Tool call budget exhausted")
            state.tool_call_count += 1
            self._emit(state, "tool_call_started")
            try:
                output = await asyncio.wait_for(
                    self._tools.call(
                        "query",
                        {"sql": plan.sql},
                        timeout_seconds=self._budget.query_timeout_seconds,
                    ),
                    timeout=self._budget.query_timeout_seconds,
                )
                self._memory.append(state.run_id, "tool_result", repr(output))
                self._emit(state, "tool_call_completed", status="completed")
                state.current_step = "result_processing"
                state.final_answer = _format_result(output)
                state.status = RunStatus.SUCCEEDED
                return
            except TimeoutError:
                category = "tool_timeout"
                retryable = True
            except ToolError as error:
                category = error.category
                retryable = error.retryable
            state.errors.append(category)
            self._memory.append(state.run_id, "error", category)
            self._emit(state, "tool_call_completed", status="failed", error_category=category)
            if not retryable:
                raise ToolError(category, category=category) from None
            if state.retry_count >= self._budget.max_retries:
                raise ToolError(category, category=category) from None
            state.retry_count += 1
            self._emit(state, "retry_started", status="retrying", error_category=category)

    def _emit(self, state: AgentState, event_type: str, **details: Any) -> None:
        self._events.emit(Event(run_id=state.run_id, event_type=event_type, **details))


class _BudgetExceeded(Exception):
    pass


class _SecurityRejected(Exception):
    pass


def _format_result(output: Any) -> str:
    if isinstance(output, str):
        return output
    return str(output)


def _error_category(error: Exception) -> str:
    if isinstance(error, _SecurityRejected):
        return "security_rejection"
    if isinstance(error, ToolError):
        return error.category
    if isinstance(error, ValueError):
        return "invalid_request"
    return "internal_error"
