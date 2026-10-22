from __future__ import annotations

import asyncio
from collections.abc import Callable
from dataclasses import dataclass
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
from sqlguard.agent.planning import Plan, Planner, RepairFeedback
from sqlguard.mcp.tools import ToolError, ToolRegistry
from sqlguard.memory.store import MemoryStore
from sqlguard.observability.events import Event, EventSink
from sqlguard.security.gate import SecurityDecision, SecurityGate
from sqlguard.security.prompting import render_denial
from sqlguard.security.service import SecurityToolError


@dataclass(frozen=True)
class RunScope:
    """Gate và tool gắn riêng với MỘT lần chạy (cùng run_id), không dùng chung giữa các request."""

    security_gate: SecurityGate
    tools: ToolRegistry
    # Kiểm tra câu trả lời cuối; trả True nếu phải giữ lại vì rò rỉ. Do runtime tin cậy dựng sẵn
    # (role lấy từ SecurityContext), không bao giờ nhận role từ câu hỏi hay đầu ra của model.
    output_check: Callable[[str], bool] | None = None


# Lỗi DB duy nhất được cho planner sửa (một lần/run); lỗi quyền, timeout, read-only, canary
# và lỗi DB khác luôn kết thúc, không bao giờ chạy lại cùng SQL.
_DB_REPAIRABLE = frozenset({"db_schema_error", "db_syntax_error"})
_SAFE_ERROR_CATEGORIES = frozenset(
    {
        "audit_error",
        "budget_exhausted",
        "cancelled",
        "canary_leak",
        "db_error",
        "db_permission_denied",
        "db_read_only_violation",
        "db_role_unconfigured",
        "db_schema_error",
        "db_syntax_error",
        "db_timeout",
        "db_unavailable",
        "event_sink_error",
        "internal_error",
        "invalid_request",
        "invalid_tool_input",
        "invalid_tool_output",
        "memory_error",
        "mcp_invalid_result",
        "mcp_tool_error",
        "mcp_transport_error",
        "output_check_error",
        "planner_call_budget_exhausted",
        "planner_error",
        "run_timeout",
        "security_gate_error",
        "security_rejection",
        "sql_attempt_budget_exhausted",
        "sql_error",
        "tool_call_budget_exhausted",
        "tool_error",
        "tool_exception",
        "tool_timeout",
        "unknown_role",
        "unknown_tool",
    }
)
_DB_REPAIR_GUIDANCE = (
    "The database rejected the previous query because of a schema or syntax problem. "
    "Propose one corrected SELECT using only tables and columns from the supplied schema notes."
)

# Nhận run_id của AgentState và trả về gate/tool đã gắn với run_id đó.
RunScopeFactory = Callable[[str], RunScope]


class AgentController:
    def __init__(
        self,
        planner: Planner,
        tools: ToolRegistry,
        security_gate: SecurityGate,
        memory: MemoryStore,
        events: EventSink,
        budget: ExecutionBudget | None = None,
        run_scope_factory: RunScopeFactory | None = None,
    ) -> None:
        self._planner = planner
        self._tools = tools
        self._security_gate = security_gate
        self._memory = memory
        self._events = events
        self._budget = budget or ExecutionBudget()
        # Nếu có factory, mỗi request tự dựng gate/tool riêng thay vì dùng gate/tool dùng chung.
        self._run_scope_factory = run_scope_factory

    async def run(self, request: AgentRequest) -> AgentResult:
        state = AgentState(request=request)
        started_at = perf_counter()
        deadline = asyncio.get_running_loop().time() + self._budget.run_timeout_seconds
        try:
            self._emit(state, "run_started")
            schema_context = getattr(self._planner, "schema_context", None)
            self._emit(
                state,
                "schema_context_ready",
                status="available" if schema_context is not None else "not_configured",
            )
            # Kiểm tra câu hỏi trước để request rỗng không tạo gate/tool/kết nối nào.
            if not request.question.strip():
                raise ValueError("Question must not be empty")
            scope = (
                self._run_scope_factory(state.run_id)
                if self._run_scope_factory
                else RunScope(self._security_gate, self._tools)
            )
            await asyncio.wait_for(
                self._execute(state, deadline, scope), timeout=self._budget.run_timeout_seconds
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

    async def _execute(self, state: AgentState, deadline: float, scope: RunScope) -> None:
        self._ensure_before_deadline(deadline)
        state.current_step = "context_retrieval"
        self._emit(state, "context_retrieval_started")
        retrieval_started = perf_counter()
        try:
            context = self._memory.get(state.run_id)
        except Exception:
            self._emit(
                state,
                "context_retrieval_completed",
                status="failed",
                error_category="memory_error",
                duration_ms=(perf_counter() - retrieval_started) * 1000,
            )
            raise _MemoryFailure from None
        self._emit(
            state,
            "context_retrieval_completed",
            status="completed",
            duration_ms=(perf_counter() - retrieval_started) * 1000,
        )

        state.current_step = "planning"
        self._ensure_before_deadline(deadline)
        if state.llm_call_count >= self._budget.max_llm_calls:
            raise _BudgetExceeded("planner_call_budget_exhausted")
        # Lần gọi planner đầu tiên: dùng chung helper với các lần repair để cùng một cách đếm
        # ngân sách, phát event và xử lý lỗi (planner lỗi luôn thành _PlannerFailure).
        sql = await self._call_planner(
            state, lambda: self._planner.create_plan(state.request.question, context)
        )

        # Cờ đảm bảo lỗi schema/cú pháp của DB chỉ được sửa tối đa MỘT lần trong mỗi run.
        db_repair_used = False
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
            gate_started = perf_counter()
            state.sql_attempt_count += 1
            try:
                decision = scope.security_gate.check(sql)
                allowed = decision.allowed
                if not isinstance(allowed, bool):
                    raise TypeError
            except Exception:
                self._emit(
                    state,
                    "security_check_completed",
                    status="failed",
                    error_category="security_gate_error",
                    duration_ms=(perf_counter() - gate_started) * 1000,
                )
                raise _SecurityGateFailure from None
            self._emit(
                state,
                "security_check_completed",
                status="allowed" if allowed else "denied",
                error_category=None if allowed else "security_rejection",
                duration_ms=(perf_counter() - gate_started) * 1000,
            )
            if not allowed:
                # Bị gate từ chối: chỉ khi denial "repairable" và planner hỗ trợ mới được sửa.
                # None nghĩa là không sửa -> giữ nguyên hành vi cũ (REFUSED, không gọi tool).
                repaired = await self._try_repair(state, deadline, context, sql, decision)
                if repaired is None:
                    raise _SecurityRejected
                # SQL sửa quay lại đầu vòng lặp để qua gate lần nữa; không bao giờ chạy thẳng.
                sql = repaired
                continue

            state.current_step = "tool_execution"
            if state.tool_call_count >= self._budget.max_tool_calls:
                raise _BudgetExceeded("tool_call_budget_exhausted")
            self._ensure_before_deadline(deadline)
            self._emit(state, "tool_call_started")
            self._emit(state, "execute_started")
            state.tool_call_count += 1
            tool_started = perf_counter()
            # Chỉ được gán khi gate ở ranh giới tool (SecureSqlTool) từ chối; mặc định là None
            # để các lỗi tool khác (timeout, db_*, canary_leak...) không đi vào đường repair.
            tool_denial: SecurityDecision | None = None
            try:
                timeout = min(
                    self._budget.query_timeout_seconds,
                    self._remaining_seconds(deadline),
                )
                output = await asyncio.wait_for(
                    scope.tools.call(
                        "query",
                        {"sql": sql},
                        timeout_seconds=timeout,
                    ),
                    timeout=timeout,
                )
            except TimeoutError:
                if asyncio.get_running_loop().time() >= deadline:
                    duration_ms = (perf_counter() - tool_started) * 1000
                    self._emit(
                        state,
                        "tool_call_completed",
                        status="failed",
                        error_category="run_timeout",
                        duration_ms=duration_ms,
                    )
                    self._emit(
                        state,
                        "execute_completed",
                        status="failed",
                        error_category="run_timeout",
                        duration_ms=duration_ms,
                    )
                    raise TimeoutError
                category = "tool_timeout"
                retryable = True
            except asyncio.CancelledError:
                duration_ms = (perf_counter() - tool_started) * 1000
                self._emit(
                    state,
                    "tool_call_completed",
                    status="failed",
                    error_category="cancelled",
                    duration_ms=duration_ms,
                )
                self._emit(
                    state,
                    "execute_completed",
                    status="failed",
                    error_category="cancelled",
                    duration_ms=duration_ms,
                )
                raise
            except ToolError as error:
                category = _safe_error_category(error.category)
                retryable = error.retryable
                # Gate ở ranh giới tool từ chối: vẫn phải qua kiểm tra repairable và budget.
                tool_denial = error.decision if isinstance(error, SecurityToolError) else None
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
                self._emit(
                    state,
                    "execute_completed",
                    status="completed",
                    duration_ms=(perf_counter() - tool_started) * 1000,
                )
                answer_started = perf_counter()
                self._emit(state, "observe_started")
                try:
                    answer = _format_result(output)
                except Exception:
                    self._emit(
                        state,
                        "observe_completed",
                        status="failed",
                        error_category="invalid_tool_output",
                        duration_ms=(perf_counter() - answer_started) * 1000,
                    )
                    raise _InvalidToolOutput from None
                # Kiểm tra rò rỉ TRƯỚC khi gán final_answer: bị chặn thì không trả gì về.
                try:
                    self._check_output(state, scope, answer)
                except ToolError as error:
                    self._emit(
                        state,
                        "observe_completed",
                        status="failed",
                        error_category=_safe_error_category(error.category),
                        duration_ms=(perf_counter() - answer_started) * 1000,
                    )
                    raise
                self._emit(
                    state,
                    "observe_completed",
                    status="completed",
                    duration_ms=(perf_counter() - answer_started) * 1000,
                )
                state.final_answer = answer
                state.status = RunStatus.SUCCEEDED
                self._emit(
                    state,
                    "answer_completed",
                    status="completed",
                    duration_ms=(perf_counter() - answer_started) * 1000,
                )
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
            self._emit(
                state,
                "execute_completed",
                status="failed",
                error_category=category,
                duration_ms=(perf_counter() - tool_started) * 1000,
            )
            # Gate của tool từ chối nhưng gate của controller đã cho qua (gate yếu hơn): vẫn phải
            # qua cùng kiểm tra repairable + ngân sách, không được lách bằng đường retry thường.
            if tool_denial is not None:
                repaired = await self._try_repair(state, deadline, context, sql, tool_denial)
                if repaired is not None:
                    sql = repaired
                    continue
            # Lỗi schema/cú pháp của DB: đúng một lần sửa mỗi run, SQL mới phải qua gate lại.
            if tool_denial is None and not db_repair_used and category in _DB_REPAIRABLE:
                db_repair_used = True
                repaired = await self._try_db_repair(state, deadline, context, sql, category)
                if repaired is not None:
                    sql = repaired
                    continue
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

    def _check_output(self, state: AgentState, scope: RunScope, answer: str) -> None:
        """Chặn câu trả lời cuối nếu rò rỉ; mọi lỗi của bước kiểm tra cũng chặn (fail closed)."""
        check = scope.output_check
        # Không có output_check (chế độ mock) thì giữ nguyên hành vi cũ.
        if check is None:
            return
        try:
            leaked = check(answer)
        except Exception:
            # Bước kiểm tra tự lỗi (kể cả ghi audit lỗi): không trả câu trả lời, fail closed.
            self._emit(
                state,
                "output_check_completed",
                status="failed",
                error_category="output_check_error",
            )
            raise ToolError("Output check failed", category="output_check_error") from None
        if leaked:
            # Event chỉ nêu danh mục; tuyệt đối không đưa câu trả lời hay giá trị bị rò vào.
            self._emit(
                state, "output_check_completed", status="blocked", error_category="canary_leak"
            )
            raise ToolError("Result withheld by output check", category="canary_leak")
        # Sạch: ghi nhận đã kiểm tra xong để event/audit phản ánh đúng diễn biến của run.
        self._emit(state, "output_check_completed", status="completed")

    async def _call_planner(self, state: AgentState, make_call: Callable[[], Any]) -> str:
        """Gọi planner một lần, tính vào ngân sách planner và phát event; trả về SQL đề xuất.

        ``make_call`` trả về coroutine của ``create_plan`` hoặc ``repair_plan``. Mọi lỗi (ngoại
        lệ, plan sai kiểu) đều đổi thành ``_PlannerFailure`` và không giữ lại thông điệp gốc, nên
        chi tiết lỗi nội bộ không lọt vào event hay state.
        """
        self._emit(state, "llm_call_started")
        self._emit(state, "sql_generation_started")
        state.llm_call_count += 1
        planner_started = perf_counter()
        try:
            plan: Plan = await make_call()
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
            self._emit(
                state,
                "sql_generation_completed",
                status="failed",
                error_category="planner_error",
                duration_ms=(perf_counter() - planner_started) * 1000,
            )
            raise _PlannerFailure from None
        except asyncio.CancelledError:
            duration_ms = (perf_counter() - planner_started) * 1000
            self._emit(
                state,
                "llm_call_completed",
                status="failed",
                error_category="cancelled",
                duration_ms=duration_ms,
            )
            self._emit(
                state,
                "sql_generation_completed",
                status="failed",
                error_category="cancelled",
                duration_ms=duration_ms,
            )
            raise
        self._emit(state, "plan_created")
        self._emit(
            state,
            "llm_call_completed",
            status="completed",
            duration_ms=(perf_counter() - planner_started) * 1000,
        )
        self._emit(
            state,
            "sql_generation_completed",
            status="completed",
            duration_ms=(perf_counter() - planner_started) * 1000,
        )
        return sql

    async def _try_repair(
        self,
        state: AgentState,
        deadline: float,
        context: tuple[str, ...],
        previous_sql: str,
        decision: SecurityDecision,
    ) -> str | None:
        """Xin planner SQL sửa cho một denial CÓ THỂ sửa; trả về SQL mới hoặc None nếu không sửa.

        None nghĩa là denial không được phép sửa (không repairable, hoặc planner không hỗ trợ):
        caller giữ nguyên hành vi kết thúc cũ. SQL mới luôn quay lại vòng lặp để qua gate lần nữa.
        Hết ngân sách thì raise ``_BudgetExceeded``; mọi lời gọi tính vào bộ đếm hiện có.
        """
        repair = getattr(self._planner, "repair_plan", None)
        # Điều kiện bắt buộc để sửa: bị từ chối, repairable đúng bằng True và planner có
        # repair_plan. Gate tự viết có thể thiếu trường repairable: coi như không được sửa.
        if (
            getattr(decision, "allowed", True)
            or getattr(decision, "repairable", False) is not True
            or not callable(repair)
        ):
            return None
        # Phản hồi gửi planner chỉ gồm SQL cũ, mã vi phạm và hướng dẫn do gate sinh ra
        # (render_denial); không có lỗi database thô hay thông điệp ngoại lệ.
        try:
            feedback = RepairFeedback(
                previous_sql=previous_sql,
                violation_codes=tuple(decision.violations),
                guidance=render_denial(decision),
            )
        except Exception:
            return None
        # Phần ngân sách/gọi planner/event dùng chung với đường sửa lỗi DB (_try_db_repair).
        return await self._request_repair(
            state, deadline, context, repair, feedback, "security_rejection"
        )

    async def _try_db_repair(
        self,
        state: AgentState,
        deadline: float,
        context: tuple[str, ...],
        previous_sql: str,
        category: str,
    ) -> str | None:
        """Cho planner đúng MỘT lần sửa SQL khi database báo lỗi schema/cú pháp.

        Chỉ nhận ``db_schema_error`` và ``db_syntax_error``; mọi lỗi DB khác (quyền, timeout,
        read-only, canary...) trả None để caller kết thúc. Planner chỉ nhận mã lỗi cố định và
        hướng dẫn cố định, không bao giờ nhận thông báo lỗi thô của database.
        """
        repair = getattr(self._planner, "repair_plan", None)
        # Planner không có repair_plan (như DemoPlanner) hoặc lỗi không thuộc nhóm sửa được: dừng.
        if category not in _DB_REPAIRABLE or not callable(repair):
            return None
        # Feedback chỉ có SQL cũ + mã lỗi cố định; SQL mới sau đó vẫn phải qua gate ở đầu vòng lặp.
        feedback = RepairFeedback(
            previous_sql=previous_sql,
            violation_codes=(category,),
            guidance=_DB_REPAIR_GUIDANCE,
        )
        return await self._request_repair(state, deadline, context, repair, feedback, category)

    async def _request_repair(
        self,
        state: AgentState,
        deadline: float,
        context: tuple[str, ...],
        repair: Callable[..., Any],
        feedback: RepairFeedback,
        category: str,
    ) -> str:
        """Phần dùng chung: kiểm tra ngân sách, gọi planner sửa và phát event metadata."""
        sql_limit = (
            self._budget.max_tool_calls
            if self._budget.max_sql_attempts is None
            else self._budget.max_sql_attempts
        )
        # Kiểm tra mọi ngân sách TRƯỚC khi gọi planner để vòng repair luôn có giới hạn trên.
        self._ensure_before_deadline(deadline)
        if state.llm_call_count >= self._budget.max_llm_calls:
            raise _BudgetExceeded("planner_call_budget_exhausted")
        if state.sql_attempt_count >= sql_limit:
            raise _BudgetExceeded("sql_attempt_budget_exhausted")
        if state.tool_call_count >= self._budget.max_tool_calls:
            raise _BudgetExceeded("tool_call_budget_exhausted")
        state.current_step = "repair"
        # Event repair chỉ mang metadata (trạng thái, nhóm lỗi), không chứa SQL hay câu hỏi.
        repair_started = perf_counter()
        self._emit(
            state,
            "repair_started",
            status="repairing",
            error_category=_safe_error_category(category),
        )
        try:
            sql = await self._call_planner(
                state, lambda: repair(state.request.question, context, feedback)
            )
        except _PlannerFailure:
            self._emit(
                state,
                "repair_completed",
                status="failed",
                error_category="planner_error",
                duration_ms=(perf_counter() - repair_started) * 1000,
            )
            raise
        except asyncio.CancelledError:
            self._emit(
                state,
                "repair_completed",
                status="failed",
                error_category="cancelled",
                duration_ms=(perf_counter() - repair_started) * 1000,
            )
            raise
        self._emit(
            state,
            "repair_completed",
            status="completed",
            duration_ms=(perf_counter() - repair_started) * 1000,
        )
        return sql

    def _emit(self, state: AgentState, event_type: str, **details: Any) -> None:
        try:
            if details.get("error_category") is not None:
                details["error_category"] = _safe_error_category(details["error_category"])
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
        return _safe_error_category(error.category)
    if isinstance(error, ValueError):
        return "invalid_request"
    return "internal_error"


def _safe_error_category(category: object) -> str:
    if isinstance(category, str) and category in _SAFE_ERROR_CATEGORIES:
        return category
    return "tool_error"
