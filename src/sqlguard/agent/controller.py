from __future__ import annotations

import asyncio
from collections.abc import Callable, Mapping
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
from sqlguard.mcp.tools import ToolCallResult, ToolError, ToolRegistry
from sqlguard.memory.store import MemoryStore
from sqlguard.observability.events import EventSink, LiveEvent, safe_error_category
from sqlguard.observability.trace import sql_artifact
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
    output_check_policy_id: str | None = None
    output_check_enabled: bool = False


# Lỗi DB duy nhất được cho planner sửa (một lần/run); lỗi quyền, timeout, read-only, canary
# và lỗi DB khác luôn kết thúc, không bao giờ chạy lại cùng SQL.
_DB_REPAIRABLE = frozenset({"db_schema_error", "db_syntax_error"})
# Database tự từ chối vì quyền (authorizer SQLite/grants) dù gate đã cho qua: đó là một lần chặn
# bảo mật nên run kết thúc REFUSED như khi gate từ chối, không retry/repair; failure_reason giữ
# nguyên category để phân biệt lớp nào đã chặn.
_DB_REFUSED = frozenset({"db_permission_denied"})
_DB_REPAIR_GUIDANCE = (
    "The database rejected the previous query because of a schema or syntax problem. "
    "Propose one corrected SELECT using only tables and columns from the supplied schema notes."
)

# Nhận run_id của AgentState và trả về gate/tool đã gắn với run_id đó.
RunScopeFactory = Callable[[str], RunScope]


def _bounded_text(value: str, limit: int = 4000) -> str:
    return value[:limit]


def _safe_violation_codes(decision: SecurityDecision) -> list[str]:
    violations = getattr(decision, "violations", ())
    return [
        violation
        for violation in violations
        if isinstance(violation, str)
        and len(violation) <= 64
        and violation.isascii()
        and violation.isidentifier()
        and violation == violation.casefold()
    ]


def _safe_identifiers(values: Any) -> list[str] | None:
    if not isinstance(values, tuple | list):
        return None
    safe_values = []
    for value in values:
        if not isinstance(value, str) or len(value) > 128:
            continue
        parts = value.split(".")
        if len(parts) <= 2 and all(part.isidentifier() for part in parts):
            safe_values.append(value)
    return safe_values


def _safe_database_access_evidence(value: Any) -> dict[str, Any] | None:
    if not isinstance(value, dict) or value.get("source") != "sqlite_authorizer":
        return None
    reads = value.get("table_columns")
    if not isinstance(reads, list):
        return None
    references = []
    for item in reads:
        if not isinstance(item, dict):
            continue
        table = item.get("table")
        column = item.get("column")
        if (
            isinstance(table, str)
            and table.isidentifier()
            and (column is None or isinstance(column, str) and column.isidentifier())
        ):
            references.append({"table": table, "column": column})
    return {
        "source": "sqlite_authorizer",
        "status": "authorized_read_references",
        "table_columns": references,
        "actual_access": "not_observed",
        "limitation": (
            "SQLite authorizer callbacks occur while statements are prepared; "
            "they do not prove which rows or columns were read."
        ),
    }


def _safe_sensitive_check(value: Any) -> dict[str, Any] | None:
    if not isinstance(value, dict):
        return None
    boundaries = {
        "request_input",
        "planner_input",
        "planner_output",
        "tool_arguments",
        "tool_output",
        "final_response",
    }
    statuses = {"pass", "violation", "not_checked", "unknown"}
    sources = {"agent_controller", "secure_sql_tool.canary_check", "runtime.output_check"}
    if (
        not isinstance(value.get("boundary"), str)
        or value["boundary"] not in boundaries
        or not isinstance(value.get("status"), str)
        or value["status"] not in statuses
        or not isinstance(value.get("source"), str)
        or value["source"] not in sources
        or value.get("check") != "policy_canary_scan"
    ):
        return None
    policy_id = value.get("policy_id")
    if policy_id is not None and (not isinstance(policy_id, str) or len(policy_id) > 128):
        return None
    reasons = {
        "boundary_not_scanned",
        "check_completed",
        "check_violation",
        "no_canaries_configured",
        "check_failed",
    }
    reason = value.get("reason")
    if reason not in reasons:
        reason = "check_failed" if value["status"] == "unknown" else "boundary_not_scanned"
    return {
        "boundary": value["boundary"],
        "status": value["status"],
        "source": value["source"],
        "check": value["check"],
        "policy_id": policy_id,
        "reason": reason,
        "redaction": "matched_values_not_recorded",
    }


def _sanitize_trace_data(data: dict[str, Any]) -> dict[str, Any]:
    safe: dict[str, Any] = {}
    for key, value in data.items():
        if key in {"counters", "budget", "request_parameters"} and isinstance(value, dict):
            safe[key] = dict(value)
        elif key == "model" and isinstance(value, str):
            safe[key] = value[:128]
        elif key in {"question", "entries", "result_preview", "value"}:
            if key == "question" and isinstance(value, str):
                safe["question"] = {"redacted": True, "characters": len(value)}
            elif key == "entries" and isinstance(value, tuple | list):
                safe["memory_entries"] = {"redacted": True, "count": len(value)}
            elif key == "result_preview" and isinstance(value, str):
                safe["result_preview"] = {"redacted": True, "characters": len(value)}
            else:
                safe[key] = {"redacted": True}
        elif key == "sql" and isinstance(value, str):
            safe["sql_artifact"] = sql_artifact(value, source="controller_event")
        elif key == "parameters" and isinstance(value, dict):
            parameters: dict[str, Any] = {}
            for name, parameter in value.items():
                if name == "sql" and isinstance(parameter, str):
                    parameters["sql_artifact"] = sql_artifact(parameter, source="tool_arguments")
                elif name in {"page", "limit", "offset"} and type(parameter) is int:
                    parameters[name] = parameter
            safe[key] = parameters
        elif key in {
            "sql_artifact",
            "sql_truncated",
            "result_truncated",
            "tool_name",
            "decision",
            "check",
            "kind",
            "policy_version",
            "gate_references_status",
            "database_execution",
            "execution_source",
            "policy_id",
            "check_enabled",
            "value_handling",
            "reason_code",
        } and isinstance(value, str | bool | int | float):
            safe[key] = value if not isinstance(value, str) else value[:128]
        elif key in {
            "violations",
            "referenced_tables",
            "referenced_columns",
            "removed_columns",
            "notices",
        }:
            safe[key] = _safe_identifiers(value) or []
        elif key == "database_access_evidence":
            access = _safe_database_access_evidence(value)
            if access is not None:
                safe[key] = access
        elif key == "sensitive_data_check":
            check = _safe_sensitive_check(value)
            if check is not None:
                safe[key] = check
    return safe


def _trace_io(
    event_type: str, data: dict[str, Any]
) -> tuple[dict[str, Any] | None, dict[str, Any] | None]:
    if event_type.endswith("_started") or event_type == "run_started":
        return data, None
    if data:
        return None, data
    return None, None


def _trace_evidence(
    event_type: str,
    status: str | None,
    data: dict[str, Any],
    error_category: str | None = None,
) -> dict[str, Any]:
    evidence: dict[str, Any] = {
        "source": "agent_controller",
        "redaction": "sql_literals_and_user_payloads_redacted",
    }
    artifact = data.get("sql_artifact")
    if not artifact and isinstance(data.get("parameters"), dict):
        artifact = data["parameters"].get("sql_artifact")
    if isinstance(artifact, dict):
        evidence["sql_artifact"] = artifact
    if event_type == "security_check_completed":
        evidence["gate_decision"] = status
        evidence["policy_version"] = data.get("policy_version")
        evidence["gate_references"] = {
            "tables": data.get("referenced_tables"),
            "columns": data.get("referenced_columns"),
            "source": "security_gate_decision",
            "status": data.get("gate_references_status", "unknown"),
        }
        evidence["omitted_columns"] = data.get("removed_columns", [])
        evidence["notices"] = data.get("notices", [])
        fields = data.get("removed_columns", [])
        evidence["field_omission"] = {
            "status": "omitted" if fields else "not_applicable",
            "fields": fields,
            "reason_code": "column_access_policy" if fields else None,
            "policy_id": data.get("policy_version"),
            "source": "security_gate_decision",
            "value_handling": "not_collected",
        }
    if event_type == "tool_call_started":
        evidence["tool_invocation"] = "started"
    if event_type == "execute_started":
        evidence["database_execution"] = "attempting"
        evidence["database_access"] = "unknown"
    if event_type == "execute_completed":
        execution = data.get("database_execution")
        if (
            execution is None
            and status == "failed"
            and error_category
            in {
                "db_error",
                "db_permission_denied",
                "db_read_only_violation",
                "db_schema_error",
                "db_syntax_error",
                "sql_error",
            }
        ):
            execution = "failed"
            evidence["execution_source"] = "database_error_category"
        evidence["database_execution"] = (
            execution if execution in {"confirmed", "failed"} else "unknown"
        )
        evidence["database_access"] = (
            data["database_access_evidence"]
            if isinstance(data.get("database_access_evidence"), dict)
            else {"status": "not_observed", "actual_access": "not_observed"}
        )
        evidence.setdefault(
            "execution_source", data.get("execution_source", "tool_registry_result")
        )
    if event_type == "output_check_completed":
        policy_id = data.get("policy_id")
        enabled = data.get("check_enabled") is True
        if data.get("check") == "policy_canary_scan" and isinstance(policy_id, str):
            check_status = (
                "violation"
                if status == "blocked"
                else "pass"
                if status == "completed" and enabled
                else "not_checked"
                if status == "completed"
                else "unknown"
            )
            check = _safe_sensitive_check(
                {
                    "boundary": "final_response",
                    "status": check_status,
                    "source": "runtime.output_check",
                    "check": "policy_canary_scan",
                    "policy_id": policy_id,
                    "reason": (
                        "check_violation"
                        if check_status == "violation"
                        else "check_completed"
                        if check_status == "pass"
                        else "no_canaries_configured"
                        if check_status == "not_checked"
                        else "check_failed"
                    ),
                }
            )
            if check is not None:
                evidence["sensitive_data_check"] = check
                evidence["sensitive_data_checks"] = {"final_response": check_status}
        else:
            evidence["sensitive_data_check"] = {
                "boundary": "final_response",
                "status": "not_checked",
                "source": "agent_controller",
                "check": "policy_canary_scan",
                "policy_id": None,
                "reason": "boundary_not_scanned",
                "redaction": "matched_values_not_recorded",
            }
            evidence["sensitive_data_checks"] = {"final_response": "not_checked"}
    sensitive_check = data.get("sensitive_data_check")
    if isinstance(sensitive_check, dict):
        evidence["sensitive_data_check"] = sensitive_check
        evidence["sensitive_data_checks"] = {sensitive_check["boundary"]: sensitive_check["status"]}
    elif event_type in {
        "run_started",
        "llm_call_started",
        "plan_created",
        "tool_call_started",
        "tool_call_completed",
    }:
        boundary = {
            "run_started": "request_input",
            "llm_call_started": "planner_input",
            "plan_created": "planner_output",
            "tool_call_started": "tool_arguments",
            "tool_call_completed": "tool_output",
        }[event_type]
        evidence["sensitive_data_check"] = {
            "boundary": boundary,
            "status": "not_checked",
            "source": "agent_controller",
            "check": "policy_canary_scan",
            "policy_id": None,
            "reason": "boundary_not_scanned",
            "redaction": "matched_values_not_recorded",
        }
        evidence["sensitive_data_checks"] = {boundary: "not_checked"}
    if event_type == "fields_omitted":
        evidence["omission_source"] = "runtime_policy"
    return evidence


def _event_module(event_type: str) -> str:
    if event_type.startswith("context_retrieval_") or event_type.startswith("memory_"):
        return "memory"
    if (
        event_type.startswith(("llm_call_", "sql_generation_", "repair_"))
        or event_type == "schema_context_ready"
        or event_type == "plan_created"
    ):
        return "planner"
    if event_type.startswith("security_check_"):
        return "security_gate"
    if event_type.startswith("tool_call_"):
        return "tool_registry"
    if event_type.startswith("execute_"):
        return "database"
    if event_type.startswith(("observe_", "output_check_", "answer_", "run_", "budget_")):
        return "controller"
    return "observability"


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
            self._emit(
                state,
                "run_started",
                data={"question": state.request.question},
            )
            schema_context = getattr(self._planner, "schema_context", None)
            # Chỉ ghi nhận schema có được cấu hình hay không; tuyệt đối không ghi nội dung schema.
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
        except _SecurityRejected as error:
            state.status = RunStatus.REFUSED
            state.failure_reason = error.reason
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
            memory_started = perf_counter()
            memory_status = "completed"
            memory_error = None
            try:
                self._memory.append(state.run_id, "state", state.status.value)
            except Exception:
                memory_status = "failed"
                memory_error = "memory_error"
                state.status = RunStatus.FAILED
                state.failure_reason = "memory_error"
                state.errors.append(state.failure_reason)
                self._set_terminal_step(state)
            try:
                self._emit(
                    state,
                    "memory_state_persisted",
                    status=memory_status,
                    error_category=memory_error,
                    duration_ms=(perf_counter() - memory_started) * 1000,
                    data=(
                        {"kind": "state", "value": state.status.value}
                        if memory_status == "completed"
                        else {"kind": "state"}
                    ),
                )
            except _EventSinkFailure:
                state.status = RunStatus.FAILED
                state.failure_reason = "event_sink_error"
                state.errors.append(state.failure_reason)
                self._set_terminal_step(state)
                try:
                    self._memory.append(state.run_id, "state", state.status.value)
                except Exception:
                    state.errors.append("memory_error")
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
        # Dùng đồng hồ thời gian thực để đo riêng bước đọc memory, không phụ thuộc đồng hồ hệ thống.
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
            data={"entries": list(context)},
        )

        state.current_step = "planning"
        self._ensure_before_deadline(deadline)
        if state.llm_call_count >= self._budget.max_llm_calls:
            raise _BudgetExceeded("planner_call_budget_exhausted")
        # Lần gọi planner đầu tiên: dùng chung helper với các lần repair để cùng một cách đếm
        # ngân sách, phát event và xử lý lỗi (planner lỗi luôn thành _PlannerFailure).
        sql = await self._call_planner(
            state, lambda: self._planner.create_plan(state.request.question, context), deadline
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
            state.related_sql_attempt_id = state.active_sql_attempt_id
            state.active_sql_attempt_id = f"sql-{state.sql_attempt_count + 1}"
            self._emit(
                state,
                "security_check_started",
                data={"sql": _bounded_text(sql), "sql_truncated": len(sql) > 4000},
            )
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
                data={
                    "decision": "allow" if allowed else "deny",
                    "kind": str(getattr(decision, "kind", "")),
                    "violations": _safe_violation_codes(decision),
                    "sql": _bounded_text(sql),
                    "policy_version": getattr(decision, "policy_version", None),
                    "referenced_tables": list(getattr(decision, "referenced_tables", ())),
                    "referenced_columns": list(getattr(decision, "referenced_columns", ())),
                    "gate_references_status": (
                        "observed"
                        if hasattr(decision, "referenced_tables")
                        and hasattr(decision, "referenced_columns")
                        else "unknown"
                    ),
                    "removed_columns": list(getattr(decision, "removed_columns", ())),
                    "notices": list(getattr(decision, "notices", ())),
                },
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
            self._emit(
                state,
                "tool_call_started",
                data={
                    "tool_name": "query",
                    "parameters": {"sql": _bounded_text(sql)},
                    "sql_truncated": len(sql) > 4000,
                },
            )
            # Đo riêng bước thực thi để trace khi tool thành công, lỗi, timeout hoặc bị hủy.
            self._emit(
                state,
                "execute_started",
                data={"sql": _bounded_text(sql), "sql_truncated": len(sql) > 4000},
            )
            state.tool_call_count += 1
            tool_started = perf_counter()
            # Chỉ được gán khi gate ở ranh giới tool (SecureSqlTool) từ chối; mặc định là None
            # để các lỗi tool khác (timeout, db_*, canary_leak...) không đi vào đường repair.
            tool_denial: SecurityDecision | None = None
            tool_error_data: dict[str, Any] = {}
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
                error_category = self._cancellation_category(deadline)
                self._emit(
                    state,
                    "tool_call_completed",
                    status="failed",
                    error_category=error_category,
                    duration_ms=duration_ms,
                )
                self._emit(
                    state,
                    "execute_completed",
                    status="failed",
                    error_category=error_category,
                    duration_ms=duration_ms,
                )
                raise
            except ToolError as error:
                category = _safe_error_category(error.category)
                retryable = error.retryable
                # Gate ở ranh giới tool từ chối: vẫn phải qua kiểm tra repairable và budget.
                tool_denial = error.decision if isinstance(error, SecurityToolError) else None
                tool_error_data = (
                    dict(error.evidence) if isinstance(error.evidence, Mapping) else {}
                )
            except Exception:
                category = "tool_exception"
                retryable = False
                tool_error_data = {}
            else:
                execution_evidence = {}
                if isinstance(output, ToolCallResult):
                    if (
                        isinstance(output.evidence, Mapping)
                        and output.evidence.get("database_execution") == "confirmed"
                        and output.evidence.get("source")
                        in {
                            "financial_database.run_page",
                            "secure_sql_tool.executor_result",
                        }
                    ):
                        execution_evidence = {
                            "database_execution": "confirmed",
                            "execution_source": output.evidence["source"],
                        }
                        if output.evidence["source"] == "secure_sql_tool.executor_result":
                            access = _safe_database_access_evidence(
                                output.evidence.get("database_access_evidence")
                            )
                            sensitive_check = _safe_sensitive_check(
                                output.evidence.get("sensitive_data_check")
                            )
                            if access is not None:
                                execution_evidence["database_access_evidence"] = access
                            if sensitive_check is not None:
                                execution_evidence["sensitive_data_check"] = sensitive_check
                    output = output.value
                self._emit(
                    state,
                    "tool_call_completed",
                    status="completed",
                    duration_ms=(perf_counter() - tool_started) * 1000,
                    data={
                        key: value
                        for key, value in execution_evidence.items()
                        if key == "sensitive_data_check"
                    },
                )
                self._emit(
                    state,
                    "execute_completed",
                    status="completed",
                    duration_ms=(perf_counter() - tool_started) * 1000,
                    data=execution_evidence,
                )
                answer_started = perf_counter()
                # Observe xử lý kết quả nhưng chỉ phát metadata, không phát nội dung kết quả.
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
                # Chỉ đánh dấu Answer hoàn tất sau khi kết quả đã qua bước kiểm tra đầu ra.
                self._emit(
                    state,
                    "answer_completed",
                    status="completed",
                    duration_ms=(perf_counter() - answer_started) * 1000,
                    data={
                        "result_preview": _bounded_text(answer, 2048),
                        "result_truncated": len(answer) > 2048,
                    },
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
                data=tool_error_data,
            )
            self._emit(
                state,
                "execute_completed",
                status="failed",
                error_category=category,
                duration_ms=(perf_counter() - tool_started) * 1000,
                data=tool_error_data,
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
            if category in _DB_REFUSED:
                raise _SecurityRejected(category)
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
        check_started = perf_counter()
        check = scope.output_check
        # A missing checker is explicit evidence absence; result handling is unchanged.
        if check is None:
            self._emit(
                state,
                "output_check_completed",
                status="not_checked",
                data={"check": "no_output_check_configured"},
            )
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
                duration_ms=(perf_counter() - check_started) * 1000,
                data={
                    "check": "policy_canary_scan",
                    "policy_id": scope.output_check_policy_id,
                    "check_enabled": scope.output_check_enabled,
                },
            )
            raise ToolError("Output check failed", category="output_check_error") from None
        if leaked:
            # Event chỉ nêu danh mục; tuyệt đối không đưa câu trả lời hay giá trị bị rò vào.
            self._emit(
                state,
                "output_check_completed",
                status="blocked",
                error_category="canary_leak",
                duration_ms=(perf_counter() - check_started) * 1000,
                data={
                    "check": "policy_canary_scan",
                    "policy_id": scope.output_check_policy_id,
                    "check_enabled": scope.output_check_enabled,
                },
            )
            raise ToolError("Result withheld by output check", category="canary_leak")
        # Sạch: ghi nhận đã kiểm tra xong để event/audit phản ánh đúng diễn biến của run.
        self._emit(
            state,
            "output_check_completed",
            status="completed",
            duration_ms=(perf_counter() - check_started) * 1000,
            data={
                "check": "policy_canary_scan",
                "policy_id": scope.output_check_policy_id,
                "check_enabled": scope.output_check_enabled,
            },
        )

    async def _call_planner(
        self, state: AgentState, make_call: Callable[[], Any], deadline: float
    ) -> str:
        """Gọi planner một lần, tính vào ngân sách planner và phát event; trả về SQL đề xuất.

        ``make_call`` trả về coroutine của ``create_plan`` hoặc ``repair_plan``. Mọi lỗi (ngoại
        lệ, plan sai kiểu) đều đổi thành ``_PlannerFailure`` và không giữ lại thông điệp gốc, nên
        chi tiết lỗi nội bộ không lọt vào event hay state.
        """
        model = getattr(self._planner, "model", None)
        planner_data = (
            {
                "model": model,
                "request_parameters": {"stream": False, "think": False, "format": "json"},
            }
            if isinstance(model, str)
            else {}
        )
        self._emit(state, "llm_call_started", data=planner_data)
        self._emit(state, "sql_generation_started", data=planner_data)
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
            error_category = self._cancellation_category(deadline)
            self._emit(
                state,
                "llm_call_completed",
                status="failed",
                error_category=error_category,
                duration_ms=duration_ms,
            )
            self._emit(
                state,
                "sql_generation_completed",
                status="failed",
                error_category=error_category,
                duration_ms=duration_ms,
            )
            raise
        plan_data = {
            **planner_data,
            "sql": _bounded_text(sql),
            "sql_truncated": len(sql) > 4000,
        }
        self._emit(state, "plan_created", data=plan_data)
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
            data=plan_data,
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
            related_attempt_id=(
                f"sql-{state.sql_attempt_count}" if state.sql_attempt_count else None
            ),
        )
        try:
            sql = await self._call_planner(
                state, lambda: repair(state.request.question, context, feedback), deadline
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
            error_category = self._cancellation_category(deadline)
            self._emit(
                state,
                "repair_completed",
                status="failed",
                error_category=error_category,
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
            # Chặn category tùy ý ở ranh giới sink để không rò dữ liệu dù caller truyền nhầm.
            if details.get("error_category") is not None:
                details["error_category"] = _safe_error_category(details["error_category"])
            if details.get("status") is None:
                if event_type == "run_started" or event_type.endswith("_started"):
                    details["status"] = "running"
                elif event_type == "plan_created":
                    details["status"] = "completed"
            data = dict(details.pop("data", {}) or {})
            data.update(
                {
                    "counters": {
                        "planner_calls": state.llm_call_count,
                        "sql_attempts": state.sql_attempt_count,
                        "tool_calls": state.tool_call_count,
                    },
                    "budget": {
                        "planner_calls": self._budget.max_llm_calls,
                        "sql_attempts": self._budget.max_sql_attempts,
                        "tool_calls": self._budget.max_tool_calls,
                        "retries": self._budget.max_retries,
                    },
                }
            )
            safe_data = _sanitize_trace_data(data)
            input_data, output_data = _trace_io(event_type, safe_data)
            evidence = _trace_evidence(
                event_type,
                details.get("status"),
                safe_data,
                details.get("error_category"),
            )
            if event_type == "run_started":
                evidence["sensitive_data_checks"] = {"request_input": "not_checked"}
            elif event_type == "llm_call_started":
                evidence["sensitive_data_checks"] = {"planner_input": "not_checked"}
            elif event_type == "plan_created":
                evidence["sensitive_data_checks"] = {"planner_output": "not_checked"}
            elif event_type == "tool_call_started":
                evidence["sensitive_data_checks"] = {"tool_arguments": "not_checked"}
            elif event_type == "tool_call_completed":
                evidence["sensitive_data_checks"] = {"tool_output": "not_checked"}
            elif event_type == "output_check_completed":
                check_configured = safe_data.get("check") == "configured_output_check"
                evidence["sensitive_data_checks"] = {
                    "final_response": (
                        "pass"
                        if check_configured and details.get("status") == "completed"
                        else "violation"
                        if check_configured and details.get("status") == "blocked"
                        else "not_checked"
                    )
                }
            attempt_id = state.active_sql_attempt_id
            if event_type.startswith(("llm_call_", "sql_generation_", "plan_created", "repair_")):
                if state.current_step == "repair" or attempt_id is None:
                    attempt_id = f"sql-{state.sql_attempt_count + 1}"
            related_attempt_id = details.pop("related_attempt_id", None)
            if related_attempt_id is None and attempt_id != state.active_sql_attempt_id:
                related_attempt_id = state.active_sql_attempt_id
            if related_attempt_id is None:
                related_attempt_id = state.related_sql_attempt_id
            self._events.emit(
                LiveEvent(
                    run_id=state.run_id,
                    event_type=event_type,
                    module=_event_module(event_type),
                    step=state.current_step,
                    attempt_id=attempt_id,
                    related_attempt_id=related_attempt_id,
                    retry_count=state.retry_count,
                    data=safe_data,
                    input=input_data,
                    output=output_data,
                    evidence=evidence,
                    **details,
                )
            )
        except Exception:
            raise _EventSinkFailure from None

    def _append_memory(self, state: AgentState, kind: str, value: str) -> None:
        try:
            self._memory.append(state.run_id, kind, value)
        except Exception:
            self._emit(
                state,
                "memory_write_completed",
                status="failed",
                error_category="memory_error",
                data={"kind": kind},
            )
            raise _MemoryFailure from None
        self._emit(
            state,
            "memory_write_completed",
            status="completed",
            data={"kind": kind, "value": value},
        )

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
    def _cancellation_category(deadline: float) -> str:
        """Phân biệt timeout của run với việc tác vụ bị caller hủy chủ động."""
        if asyncio.get_running_loop().time() >= deadline:
            return "run_timeout"
        return "cancelled"

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
    """Từ chối bảo mật kết thúc run là REFUSED; ``reason`` được ghi vào ``failure_reason``."""

    def __init__(self, reason: str = "security_rejection") -> None:
        super().__init__(reason)
        self.reason = reason


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
    """Đổi ngoại lệ thành mã an toàn trước khi ghi vào trạng thái run."""
    if isinstance(error, _InvalidToolOutput):
        return "invalid_tool_output"
    if isinstance(error, ToolError):
        # ToolError có thể đến từ tích hợp ngoài nên category không mặc nhiên được tin cậy.
        return _safe_error_category(error.category)
    if isinstance(error, ValueError):
        return "invalid_request"
    return "internal_error"


def _safe_error_category(category: object) -> str:
    """Giữ nguyên category đã biết; thay category lạ bằng mã chung không nhạy cảm."""
    return safe_error_category(category)
