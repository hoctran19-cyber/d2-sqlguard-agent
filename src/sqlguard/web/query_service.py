"""Chạy câu hỏi qua AgentController và trả kết quả cho trang Query.

Chế độ financial giữ planner demo legacy. Chế độ synthetic SQLite dùng Ollama cùng runtime
PolicySQLGate/SecureSqlTool/SQLiteExecutor hiện có; không có đường thực thi SQL song song.
"""

from __future__ import annotations

import asyncio
import json
import os
from collections.abc import Mapping
from dataclasses import asdict
from pathlib import Path
from time import perf_counter
from typing import Any

from sqlguard.agent.controller import AgentController, RunScope
from sqlguard.agent.models import AgentRequest, ExecutionBudget, RunStatus
from sqlguard.agent.planning import OllamaPlanner, Plan, PlannerConfigError
from sqlguard.agent.postgres_schema import SchemaAdapterError
from sqlguard.agent.runtime import (
    QUERY_SOURCE_ENV,
    SCHEMA_SOURCE_ENV,
    QueryRuntimeError,
    build_query_runtime_factory,
    create_planner_for_role,
)
from sqlguard.agent.sqlite_schema import SQLITE_PATH_ENV
from sqlguard.mcp.tools import InProcessToolRegistry, ToolError, ToolRegistry
from sqlguard.memory.store import InMemoryMemory
from sqlguard.observability.events import InMemoryEventSink
from sqlguard.security.gate import PolicySQLGate, ReadOnlySQLGate, SecurityDecision
from sqlguard.security.policy import RolePolicy, load_policy
from sqlguard.web.database import (
    DatabaseUnavailable,
    FinancialDatabase,
    PageResult,
    QueryError,
    QueryTimeout,
)
from sqlguard.web.demo_planner import PLANNER_NAME, SAMPLE_QUESTIONS, DemoFinancialPlanner

# Lý do từ chối của Gate (mã lỗi tiếng Anh) -> câu giải thích tiếng Việt cho người dùng.
GATE_REASONS = {
    "empty_sql": "Câu SQL đang trống.",
    "parse_error": "Không phân tích được câu SQL.",
    "multiple_statements": "Chỉ được chạy đúng một câu lệnh SQL.",
    "not_select": "Chỉ cho phép câu lệnh SELECT chỉ đọc; lệnh ghi/xóa bị chặn.",
    "table_not_allowed": "Câu SQL dùng bảng nằm ngoài danh sách được phép.",
}

WEB_QUERY_MODE_ENV = "SQLGUARD_WEB_QUERY_MODE"
WEB_QUERY_DB_ENV = "SQLGUARD_WEB_DEMO_SQLITE_PATH"
LEGACY_QUERY_MODE = "financial"
SYNTHETIC_QUERY_MODE = "synthetic_sqlite"
SYNTHETIC_POLICY_NAME = "d2_synthetic_v1"
SYNTHETIC_ROLE = "sales"
SYNTHETIC_QUESTION = "List order IDs and total amounts"


class WebQueryConfigurationError(Exception):
    """Safe Web query configuration category."""

    def __init__(self, category: str) -> None:
        super().__init__(category)
        self.category = category


def web_query_mode(env: Mapping[str, str] | None = None) -> str:
    env = os.environ if env is None else env
    mode = (env.get(WEB_QUERY_MODE_ENV) or LEGACY_QUERY_MODE).casefold()
    if mode not in {LEGACY_QUERY_MODE, SYNTHETIC_QUERY_MODE}:
        raise WebQueryConfigurationError("query_mode_invalid")
    return mode


def query_sample_payload(env: Mapping[str, str] | None = None) -> dict[str, Any]:
    env = os.environ if env is None else env
    if web_query_mode(env) == SYNTHETIC_QUERY_MODE:
        return {
            "mode": SYNTHETIC_QUERY_MODE,
            "planner": (env.get("SQLGUARD_PLANNER") or "demo").casefold(),
            "model": env.get("SQLGUARD_OLLAMA_MODEL") or "qwen3:8b",
            "questions": [SYNTHETIC_QUESTION],
        }
    return {
        "mode": LEGACY_QUERY_MODE,
        "planner": PLANNER_NAME,
        "model": None,
        "questions": list(SAMPLE_QUESTIONS),
    }


def build_gate(table_names: list[str]) -> ReadOnlySQLGate:
    """Gate của B: chỉ một câu SELECT, chỉ trên các bảng financial."""
    return ReadOnlySQLGate(set(table_names))


def explain_denial(decision: SecurityDecision) -> str:
    code = decision.violations[0] if decision.violations else ""
    return GATE_REASONS.get(code, decision.reason)


def build_planner() -> DemoFinancialPlanner:
    """Điểm thay thế duy nhất: khi A có LLM planner thật, trả planner đó ở đây."""
    return DemoFinancialPlanner()


class RecordingGate:
    """Bọc Gate để nhớ quyết định cuối cùng (UI cần lý do khi bị từ chối)."""

    def __init__(self, gate: ReadOnlySQLGate) -> None:
        self._gate = gate
        self.last_decision: SecurityDecision | None = None

    def check(self, sql: str) -> SecurityDecision:
        self.last_decision = self._gate.check(sql)
        return self.last_decision


class FinancialQueryTool:
    """Tool "query" cho Controller: chạy SQL đã qua Gate và lấy trang dữ liệu đầu tiên."""

    name = "query"
    input_schema = {
        "type": "object",
        "required": ["sql"],
        "properties": {"sql": {"type": "string"}},
    }
    output_schema = {"type": "string"}

    def __init__(self, database: FinancialDatabase) -> None:
        self._database = database
        self.last_result: PageResult | None = None

    async def call(self, arguments, *, timeout_seconds):
        sql = arguments.get("sql")
        if not isinstance(sql, str):
            raise ToolError("SQL is required", category="invalid_tool_input", retryable=False)
        try:
            # Chạy SQLite trong thread riêng để không chặn event loop của server.
            self.last_result = await asyncio.to_thread(
                self._database.run_page, sql, page=1, timeout_seconds=timeout_seconds
            )
        except QueryTimeout:
            raise ToolError("query timeout", category="tool_timeout", retryable=False) from None
        except QueryError:
            raise ToolError("query failed", category="sql_error", retryable=False) from None
        except DatabaseUnavailable:
            raise ToolError("db unavailable", category="db_unavailable", retryable=False) from None
        return json.dumps({"total_rows": self.last_result.total_rows})


async def answer_question(
    database: FinancialDatabase,
    question: str,
    env: Mapping[str, str] | None = None,
) -> dict:
    """Trả về dict cho API /api/query. status: full | partial | refused | failed."""
    env = os.environ if env is None else env
    if web_query_mode(env) == SYNTHETIC_QUERY_MODE:
        return await _answer_synthetic_question(question, env)

    started = perf_counter()
    planner = build_planner()
    base = {"question": question, "planner": PLANNER_NAME, "omitted_fields": []}

    # Planner demo không hiểu câu hỏi tự do: báo rõ thay vì đoán bừa SQL.
    if not planner.supports(question):
        return {
            **base,
            "run_id": None,
            "status": "failed",
            "reason": "Chưa tích hợp LLM: planner demo chỉ trả lời được các câu hỏi mẫu.",
            "sql": None,
            "result": None,
            "events": [],
            "duration_ms": (perf_counter() - started) * 1000,
        }

    gate = RecordingGate(build_gate(database.table_names()))
    tool = FinancialQueryTool(database)
    events = InMemoryEventSink()
    controller = AgentController(
        planner=planner,
        tools=InProcessToolRegistry([tool]),
        security_gate=gate,
        memory=InMemoryMemory(),
        events=events,
        budget=ExecutionBudget(max_sql_attempts=1),  # Planner demo không có khả năng tự sửa SQL.
    )
    state = (await controller.run(AgentRequest(question))).state

    if state.status == RunStatus.SUCCEEDED and tool.last_result is not None:
        status, reason = "full", "Trả lời đầy đủ: câu SQL được phép và đã chạy thành công."
    elif state.status == RunStatus.REFUSED and gate.last_decision is not None:
        status, reason = "refused", explain_denial(gate.last_decision)
    else:
        status, reason = "failed", f"Không có kết quả đáng tin cậy ({state.failure_reason})."

    return {
        **base,
        "run_id": state.run_id,
        "status": status,
        "reason": reason,
        "sql": planner.last_sql,
        "result": tool.last_result.to_dict() if status == "full" else None,
        "events": [
            {"type": e["event_type"], "status": e["status"]} for e in map(asdict, events.events)
        ],
        "duration_ms": (perf_counter() - started) * 1000,
    }


class _WebRecordingGate:
    def __init__(self, gate: PolicySQLGate) -> None:
        self._gate = gate
        self.last_decision: SecurityDecision | None = None

    def check(self, sql: str) -> SecurityDecision:
        self.last_decision = self._gate.check(sql)
        return self.last_decision


class _WebRecordingRegistry:
    def __init__(self, registry: ToolRegistry) -> None:
        self._registry = registry
        self.result: dict[str, Any] | None = None

    async def call(self, name: str, arguments: dict[str, Any], *, timeout_seconds: float) -> Any:
        result = await self._registry.call(name, arguments, timeout_seconds=timeout_seconds)
        if name == "query" and isinstance(result, dict):
            self.result = result
        return result


class _WebRecordingPlanner:
    def __init__(self, planner: OllamaPlanner) -> None:
        self._planner = planner
        self.model = planner.model
        self.schema_context = planner.schema_context
        self.last_sql: str | None = None

    async def create_plan(self, question: str, context: tuple[str, ...]) -> Plan:
        plan = await self._planner.create_plan(question, context)
        self.last_sql = plan.sql
        return plan


def _safe_policy_reason(decision: SecurityDecision | None) -> str:
    if decision is None:
        return "Chưa có quyết định từ Security Gate."
    if decision.allowed:
        return "Câu truy vấn được policy cho phép."
    safe_reasons = {
        "write_operation": "Chỉ cho phép truy vấn SELECT chỉ đọc.",
        "multiple_statements": "Chỉ cho phép một câu SQL.",
        "table_not_allowed": "Truy vấn tham chiếu bảng ngoài policy.",
        "column_not_allowed": "Truy vấn tham chiếu cột ngoài policy.",
        "star_not_allowed": "Policy không cho phép chọn tất cả cột.",
    }
    return next(
        (safe_reasons[code] for code in decision.violations if code in safe_reasons),
        "Câu truy vấn bị Security Gate từ chối theo policy.",
    )


def _safe_runtime_reason(category: str | None) -> str:
    return {
        "planner_error": (
            "Ollama không trả được kế hoạch hợp lệ; kiểm tra dịch vụ, model và timeout."
        ),
        "db_unavailable": "Không thể truy cập database demo đã cấu hình.",
        "db_timeout": "Truy vấn vượt quá thời gian cho phép.",
        "db_schema_error": "Truy vấn không khớp schema database demo.",
        "db_syntax_error": "Database không chấp nhận cú pháp truy vấn.",
        "db_error": "Database không thể hoàn tất truy vấn.",
        "security_rejection": "Security Gate đã từ chối câu truy vấn.",
        "run_timeout": "Lần chạy vượt quá thời gian cho phép.",
    }.get(category or "", "Không thể hoàn tất lần chạy; không có kết quả được trả về.")


async def _answer_synthetic_question(question: str, env: Mapping[str, str]) -> dict:
    started = perf_counter()
    configured_path = env.get(WEB_QUERY_DB_ENV)
    if not configured_path or not configured_path.strip():
        raise WebQueryConfigurationError("synthetic_database_path_missing")
    database_path = Path(configured_path).expanduser()
    if not database_path.is_file():
        raise WebQueryConfigurationError("synthetic_database_missing")
    planner_name = (env.get("SQLGUARD_PLANNER") or "demo").casefold()
    if planner_name != "ollama":
        raise WebQueryConfigurationError("synthetic_mode_requires_ollama")

    runtime_env = dict(env)
    runtime_env.update(
        {
            "SQLGUARD_PLANNER": "ollama",
            SCHEMA_SOURCE_ENV: "sqlite",
            QUERY_SOURCE_ENV: "sqlite",
            SQLITE_PATH_ENV: str(database_path),
        }
    )
    policy: RolePolicy = load_policy(SYNTHETIC_POLICY_NAME)
    try:
        planner = await create_planner_for_role(SYNTHETIC_ROLE, runtime_env, policy=policy)
        if not isinstance(planner, OllamaPlanner):
            raise WebQueryConfigurationError("synthetic_mode_requires_ollama")
        query_factory = build_query_runtime_factory(
            SYNTHETIC_ROLE,
            runtime_env,
            policy=policy,
        )
    except WebQueryConfigurationError:
        raise
    except SchemaAdapterError as error:
        raise WebQueryConfigurationError(error.category) from None
    except QueryRuntimeError as error:
        raise WebQueryConfigurationError(error.category) from None
    except PlannerConfigError:
        raise WebQueryConfigurationError("planner_configuration_invalid") from None

    if query_factory is None:
        raise WebQueryConfigurationError("query_runtime_unavailable")
    recording_planner = _WebRecordingPlanner(planner)
    gate: _WebRecordingGate | None = None
    registry: _WebRecordingRegistry | None = None
    events = InMemoryEventSink()

    def scope_factory(run_id: str) -> RunScope:
        nonlocal gate, registry
        runtime = query_factory.for_run(run_id)
        gate = _WebRecordingGate(runtime.gate)
        registry = _WebRecordingRegistry(InProcessToolRegistry([runtime.tool]))
        return RunScope(gate, registry, output_check=runtime.output_check)

    controller = AgentController(
        planner=recording_planner,
        tools=InProcessToolRegistry([]),
        security_gate=ReadOnlySQLGate(),
        memory=InMemoryMemory(),
        events=events,
        budget=ExecutionBudget(max_sql_attempts=1),
        run_scope_factory=scope_factory,
    )
    state = (await controller.run(AgentRequest(question))).state
    decision = gate.last_decision if gate else None
    result = registry.result if registry else None
    gate_status = "ALLOW" if decision and decision.allowed else "BLOCK" if decision else "NOT_RUN"
    succeeded = state.status == RunStatus.SUCCEEDED and result is not None
    if succeeded:
        status = "full"
        reason = "Truy vấn đã qua policy gate và được thực thi trên SQLite tổng hợp."
    elif state.status == RunStatus.REFUSED:
        status = "refused"
        reason = _safe_policy_reason(decision)
    else:
        status = "failed"
        reason = _safe_runtime_reason(state.failure_reason)

    page_result = None
    if succeeded and result is not None:
        rows = result.get("rows", [])
        columns = result.get("columns", [])
        row_count = len(rows)
        page_result = {
            "sql": result.get("executed_sql", recording_planner.last_sql),
            "columns": columns,
            "rows": rows,
            "page": 1,
            "page_size": row_count,
            "total_rows": row_count,
            "total_pages": 1,
            "truncated": result.get("truncated", False),
        }

    return {
        "backend": SYNTHETIC_QUERY_MODE,
        "question": question,
        "planner": "ollama",
        "model": recording_planner.model,
        "run_id": state.run_id,
        "status": status,
        "reason": reason,
        "execution_status": state.status.value,
        "sql": recording_planner.last_sql,
        "gate": {"status": gate_status, "reason": _safe_policy_reason(decision)},
        "result": page_result,
        "row_count": page_result["total_rows"] if page_result else 0,
        "truncated": page_result["truncated"] if page_result else False,
        "events": [{"type": event.event_type, "status": event.status} for event in events.events],
        "duration_ms": (perf_counter() - started) * 1000,
    }
