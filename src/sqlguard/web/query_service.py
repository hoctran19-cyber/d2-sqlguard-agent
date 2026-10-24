"""Chạy câu hỏi qua AgentController và trả kết quả cho trang Query.

Chế độ financial giữ planner demo legacy. Chế độ synthetic SQLite dùng planner LLM (Ollama hoặc
Gemini, theo ``SQLGUARD_PLANNER``) cùng runtime
PolicySQLGate/SecureSqlTool/SQLiteExecutor hiện có; không có đường thực thi SQL song song.
Ba role nghiệp vụ dùng cùng runtime đó với policy ``business_financial_v1`` và role lấy từ phiên
đăng nhập, chỉ khi ``SQLGUARD_BUSINESS_FINANCIAL_DB`` trỏ tới database đạt schema preflight.
"""

from __future__ import annotations

import asyncio
import json
import os
from collections.abc import Mapping
from datetime import UTC
from pathlib import Path
from time import perf_counter
from typing import Any
from uuid import uuid4

from sqlguard.agent.controller import AgentController, RunScope
from sqlguard.agent.models import AgentRequest, ExecutionBudget, RunStatus
from sqlguard.agent.planning import LLMPlanner, Plan, PlannerConfigError
from sqlguard.agent.postgres_schema import SchemaAdapterError
from sqlguard.agent.runtime import (
    QUERY_SOURCE_ENV,
    SCHEMA_SOURCE_ENV,
    QueryRuntimeError,
    build_query_runtime_factory,
    create_planner_for_role,
)
from sqlguard.agent.sqlite_schema import SQLITE_PATH_ENV
from sqlguard.mcp.tools import InProcessToolRegistry, ToolCallResult, ToolError, ToolRegistry
from sqlguard.memory.store import InMemoryMemory
from sqlguard.observability.events import (
    CompositeEventSink,
    Event,
    EventSink,
    InMemoryEventSink,
    SQLiteEventStore,
)
from sqlguard.security.business_database import (
    BUSINESS_DATABASE_ENV,
    check_business_database_readiness,
)
from sqlguard.security.gate import PolicySQLGate, ReadOnlySQLGate, SecurityDecision
from sqlguard.security.policy import RolePolicy, load_policy
from sqlguard.security.service import SecurityToolError
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
BUSINESS_QUERY_MODE = "business_sqlite"
BUSINESS_POLICY_NAME = "business_financial_v1"
MAX_SQL_ATTEMPTS_ENV = "SQLGUARD_WEB_MAX_SQL_ATTEMPTS"
RUN_TIMEOUT_ENV = "SQLGUARD_RUN_TIMEOUT_SECONDS"
# Câu hỏi gợi ý cho từng role; câu cuối cố ý chạm giới hạn của role để thấy partial/refusal.
BUSINESS_SAMPLE_QUESTIONS = {
    "operator": (
        "Cho biết mã tài khoản, tần suất sao kê và ghi chú dịch vụ của tài khoản 3.",
        "Liệt kê 5 giao dịch gần nhất của tài khoản 1 kèm số dư sau giao dịch.",
        "Cho biết họ tên và số định danh (id_number) của khách hàng 4.",
    ),
    "analyst": (
        "Có bao nhiêu tài khoản theo từng tần suất sao kê?",
        "Tổng số tiền giao dịch vào và ra theo từng vùng.",
        "Liệt kê 10 giao dịch có số tiền lớn nhất kèm mã tài khoản.",
    ),
    "credit_officer": (
        "Có bao nhiêu khoản vay theo từng trạng thái?",
        "Liệt kê các khoản vay trạng thái D kèm họ tên chủ tài khoản.",
        "Cho biết địa chỉ của chủ các khoản vay trạng thái D.",
    ),
}


class WebQueryConfigurationError(Exception):
    """Safe Web query configuration category."""

    def __init__(self, category: str) -> None:
        super().__init__(category)
        self.category = category


def _event_payload(event: Event) -> dict[str, Any]:
    """Keep the synchronous Query response metadata-only; live artifacts use authenticated SSE."""
    return {
        "run_id": event.run_id,
        "event_type": event.event_type,
        "timestamp": event.timestamp.astimezone(UTC).isoformat(),
        "status": event.status,
        "duration_ms": event.duration_ms,
        "error_category": event.error_category,
        "type": event.event_type,
    }


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


def business_database_path(env: Mapping[str, str] | None = None) -> Path | None:
    """Đường dẫn DB nghiệp vụ nếu đã cấu hình và đạt preflight; kiểm lại ở mỗi lần gọi."""
    env = os.environ if env is None else env
    configured = env.get(BUSINESS_DATABASE_ENV) or ""
    if not check_business_database_readiness(configured).ready:
        return None
    return Path(configured).expanduser()


def business_queries_enabled(env: Mapping[str, str] | None = None) -> bool:
    return business_database_path(env) is not None


def business_policy() -> RolePolicy:
    return load_policy(BUSINESS_POLICY_NAME)


def business_sample_payload(role: str, env: Mapping[str, str] | None = None) -> dict[str, Any]:
    env = os.environ if env is None else env
    return {
        "mode": BUSINESS_QUERY_MODE,
        "role": role,
        "policy": business_policy().version,
        "planner": (env.get("SQLGUARD_PLANNER") or "demo").casefold(),
        "model": env.get("SQLGUARD_OLLAMA_MODEL") or "qwen3:8b",
        "questions": list(BUSINESS_SAMPLE_QUESTIONS.get(role, ())),
    }


def business_table_payload(role: str) -> dict[str, Any]:
    """Bảng role được dùng và câu SQL mặc định hợp lệ cho trang Database (không chạm DB)."""
    policy = business_policy()
    tables = sorted(policy.allowed_tables(role))
    default_sql = {}
    for table in tables:
        quoted = f'"{table}"'
        if policy.is_aggregate_only(role):
            default_sql[table] = f"SELECT COUNT(*) AS row_count FROM {quoted}"
        else:
            columns = ", ".join(c for c in policy.tables[table] if policy.can_read(role, table, c))
            default_sql[table] = f"SELECT {columns} FROM {quoted}"
    return {
        "database": "financial",
        "policy": policy.version,
        "tables": tables,
        "default_sql": default_sql,
    }


def _max_sql_attempts(backend: str, env: Mapping[str, str]) -> int:
    """Synthetic giữ 1 lần; business cho model sửa SQL bị từ chối (mặc định 3, tối đa 5)."""
    if backend != BUSINESS_QUERY_MODE:
        return 1
    try:
        return min(max(int(env.get(MAX_SQL_ATTEMPTS_ENV) or 3), 1), 5)
    except ValueError:
        return 3


def _web_budget(backend: str, env: Mapping[str, str]) -> ExecutionBudget:
    """Business nhận ``SQLGUARD_RUN_TIMEOUT_SECONDS`` như CLI (model local trên CPU rất chậm)."""
    attempts = _max_sql_attempts(backend, env)
    if backend != BUSINESS_QUERY_MODE:
        return ExecutionBudget(max_sql_attempts=attempts)
    try:
        timeout = float(env.get(RUN_TIMEOUT_ENV) or 60.0)
    except ValueError:
        timeout = 60.0
    return ExecutionBudget(
        max_sql_attempts=attempts, run_timeout_seconds=timeout if timeout > 0 else 60.0
    )


class BusinessSqlDenied(Exception):
    """SQL thủ công bị Security Gate từ chối; ``reason`` là câu giải thích an toàn."""

    def __init__(self, decision: SecurityDecision) -> None:
        super().__init__(decision.reason)
        self.decision = decision
        self.reason = _safe_policy_reason(decision)


async def run_business_sql(
    sql: str, role: str, user_id: str, env: Mapping[str, str] | None = None
) -> dict[str, Any]:
    """SQL thủ công của role nghiệp vụ: cùng gate + SecureSqlTool + authorizer với agent.

    Chỉ chạy ``normalized_sql`` của gate, trả tối đa ``max_rows`` dòng trong một trang và không
    bao giờ trả lỗi database nguyên văn.
    """
    env = os.environ if env is None else env
    database_path = business_database_path(env)
    if database_path is None:
        raise WebQueryConfigurationError("business_database_not_ready")
    policy = business_policy()
    runtime_env = {
        QUERY_SOURCE_ENV: "sqlite",
        SQLITE_PATH_ENV: str(database_path),
        **{key: env[key] for key in ("SQLGUARD_AUDIT_PATH",) if env.get(key)},
    }
    try:
        factory = build_query_runtime_factory(role, runtime_env, policy=policy)
    except QueryRuntimeError as error:
        raise WebQueryConfigurationError(error.category) from None
    runtime = factory.for_run(str(uuid4()), user_id=user_id, request_mode="manual_sql")
    try:
        envelope = await runtime.tool.call(
            {"sql": sql}, timeout_seconds=policy.limits.query_timeout_seconds
        )
    except SecurityToolError as error:
        raise BusinessSqlDenied(error.decision) from None
    except ToolError as error:
        raise QueryError(error.category) from None
    rows = envelope["rows"]
    return {
        "sql": envelope["executed_sql"],
        "columns": envelope["columns"],
        "rows": rows,
        "page": 1,
        "page_size": len(rows),
        "total_rows": len(rows),
        "total_pages": 1,
        "truncated": envelope["truncated"],
        "removed_columns": envelope.get("removed_columns", []),
        "small_groups_withheld": envelope.get("small_groups_withheld", False),
        "policy_version": envelope.get("policy_version"),
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
        return ToolCallResult(
            value=json.dumps({"total_rows": self.last_result.total_rows}),
            evidence={
                "database_execution": "confirmed",
                "source": "financial_database.run_page",
            },
        )


async def answer_question(
    database: FinancialDatabase,
    question: str,
    env: Mapping[str, str] | None = None,
    *,
    run_id: str | None = None,
    live_sink: EventSink | None = None,
) -> dict:
    """Trả về dict cho API /api/query. status: full | partial | refused | failed."""
    env = os.environ if env is None else env
    if web_query_mode(env) == SYNTHETIC_QUERY_MODE:
        return await _answer_synthetic_question(
            question,
            env,
            run_id=run_id,
            live_sink=live_sink,
        )

    started = perf_counter()
    planner = build_planner()
    base = {"question": question, "planner": PLANNER_NAME, "omitted_fields": []}

    # Planner demo không hiểu câu hỏi tự do: báo rõ thay vì đoán bừa SQL.
    if not planner.supports(question):
        return {
            **base,
            "run_id": run_id,
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
    sinks: tuple[EventSink, ...] = (events, SQLiteEventStore.from_env(env))
    if live_sink is not None:
        sinks += (live_sink,)
    event_sink = CompositeEventSink(sinks)
    controller = AgentController(
        planner=planner,
        tools=InProcessToolRegistry([tool]),
        security_gate=gate,
        memory=InMemoryMemory(),
        events=event_sink,
        budget=ExecutionBudget(max_sql_attempts=1),  # Planner demo không có khả năng tự sửa SQL.
    )
    state = (await controller.run(AgentRequest(question, run_id=run_id))).state

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
        "events": [_event_payload(event) for event in events.events],
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
    def __init__(self, registry: ToolRegistry, secure_tool) -> None:
        self._registry = registry
        self._secure_tool = secure_tool
        self.result: dict[str, Any] | None = None

    async def call(self, name: str, arguments: dict[str, Any], *, timeout_seconds: float) -> Any:
        result = await self._registry.call(name, arguments, timeout_seconds=timeout_seconds)
        if name == "query" and isinstance(result, dict):
            self.result = result
            if result.get("source") == "database" and isinstance(result.get("executed_sql"), str):
                evidence = {
                    "database_execution": "confirmed",
                    "source": "secure_sql_tool.executor_result",
                }
                trace_evidence = getattr(self._secure_tool, "last_trace_evidence", None)
                if isinstance(trace_evidence, Mapping):
                    evidence.update(trace_evidence)
                return ToolCallResult(
                    value=result,
                    evidence=evidence,
                )
        return result


class _WebRecordingPlanner:
    def __init__(self, planner: LLMPlanner) -> None:
        self._planner = planner
        self.provider = planner.provider
        self.request_parameters = planner.request_parameters
        self.model = planner.model
        self.schema_context = planner.schema_context
        self.last_sql: str | None = None

    async def create_plan(self, question: str, context: tuple[str, ...]) -> Plan:
        plan = await self._planner.create_plan(question, context)
        self.last_sql = plan.sql
        return plan


class _WebRepairingPlanner(_WebRecordingPlanner):
    """Chế độ business: cho model sửa SQL bị gate từ chối (repairable); bản sửa lại qua gate.

    Lớp riêng vì controller nhận biết khả năng sửa qua sự có mặt của ``repair_plan``; chế độ
    synthetic giữ nguyên hành vi không sửa.
    """

    async def repair_plan(self, question: str, context: tuple[str, ...], feedback) -> Plan:
        plan = await self._planner.repair_plan(question, context, feedback)
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
        "not_select": "Chỉ cho phép truy vấn SELECT chỉ đọc.",
        "system_catalog": "Không được truy vấn bảng hệ thống.",
        "table_not_allowed": "Truy vấn tham chiếu bảng ngoài policy.",
        "column_not_allowed": "Truy vấn tham chiếu cột ngoài policy.",
        "column_forbidden": "Truy vấn dùng cột mà role này không được đọc (kể cả để lọc/sắp xếp).",
        "column_forbidden_narrowable": (
            "Truy vấn hiển thị hoặc nhóm theo cột role này không được đọc."
        ),
        "aggregate_key_exposed": (
            "Role chỉ tổng hợp: khóa cá thể chỉ được dùng để JOIN hoặc COUNT, không được xuất, "
            "nhóm hay lọc theo."
        ),
        "aggregate_measure_exposed": "Role chỉ tổng hợp: số liệu chỉ được dùng trong hàm tổng hợp.",
        "aggregate_required": "Role này chỉ được nhận kết quả tổng hợp, không được xuất từng dòng.",
        "constant_projection": "Câu truy vấn trả giá trị hằng thay vì dữ liệu đọc từ bảng.",
        "question_needs_forbidden_data": (
            "Câu hỏi cần dữ liệu ngoài quyền của role này; truy vấn của model trả lời một câu "
            "hỏi khác nên bị từ chối."
        ),
        "star_not_allowed": "Policy không cho phép chọn tất cả cột.",
        "subquery_not_supported": "Subquery chưa được hỗ trợ.",
        "join_not_allowed": "Chỉ cho phép JOIN theo khóa ngoại đã khai báo.",
        "column_unknown": "Truy vấn tham chiếu cột không tồn tại.",
        "parse_error": "Không phân tích được câu SQL.",
    }
    return next(
        (safe_reasons[code] for code in decision.violations if code in safe_reasons),
        "Câu truy vấn bị Security Gate từ chối theo policy.",
    )


def _safe_runtime_reason(category: str | None) -> str:
    return {
        "planner_error": (
            "Planner LLM không trả được kế hoạch hợp lệ; kiểm tra dịch vụ, model và timeout."
        ),
        "planner_blocked": "Bộ lọc an toàn của nhà cung cấp LLM đã chặn yêu cầu.",
        "db_unavailable": "Không thể truy cập database demo đã cấu hình.",
        "db_timeout": "Truy vấn vượt quá thời gian cho phép.",
        "db_schema_error": "Truy vấn không khớp schema database demo.",
        "db_syntax_error": "Database không chấp nhận cú pháp truy vấn.",
        "db_error": "Database không thể hoàn tất truy vấn.",
        "security_rejection": "Security Gate đã từ chối câu truy vấn.",
        "sql_attempt_budget_exhausted": (
            "Model chưa viết được câu SQL hợp lệ trong số lần thử cho phép; Security Gate đã "
            "từ chối mọi bản nháp và không có truy vấn nào được thực thi."
        ),
        "run_timeout": "Lần chạy vượt quá thời gian cho phép.",
    }.get(category or "", "Không thể hoàn tất lần chạy; không có kết quả được trả về.")


async def _answer_synthetic_question(
    question: str,
    env: Mapping[str, str],
    *,
    run_id: str | None = None,
    live_sink: EventSink | None = None,
) -> dict:
    configured_path = env.get(WEB_QUERY_DB_ENV)
    if not configured_path or not configured_path.strip():
        raise WebQueryConfigurationError("synthetic_database_path_missing")
    database_path = Path(configured_path).expanduser()
    if not database_path.is_file():
        raise WebQueryConfigurationError("synthetic_database_missing")
    return await _answer_with_policy(
        question,
        env,
        policy=load_policy(SYNTHETIC_POLICY_NAME),
        role=SYNTHETIC_ROLE,
        database_path=database_path,
        backend=SYNTHETIC_QUERY_MODE,
        run_id=run_id,
        live_sink=live_sink,
    )


async def answer_business_question(
    question: str,
    role: str,
    env: Mapping[str, str] | None = None,
    *,
    user_id: str,
    run_id: str | None = None,
    live_sink: EventSink | None = None,
) -> dict:
    """Câu hỏi của role nghiệp vụ; ``role`` và ``user_id`` chỉ lấy từ phiên đăng nhập."""
    env = os.environ if env is None else env
    database_path = business_database_path(env)
    if database_path is None:
        raise WebQueryConfigurationError("business_database_not_ready")
    return await _answer_with_policy(
        question,
        env,
        policy=business_policy(),
        role=role,
        database_path=database_path,
        backend=BUSINESS_QUERY_MODE,
        user_id=user_id,
        run_id=run_id,
        live_sink=live_sink,
    )


async def _answer_with_policy(
    question: str,
    env: Mapping[str, str],
    *,
    policy: RolePolicy,
    role: str,
    database_path: Path,
    backend: str,
    user_id: str = "web",
    run_id: str | None = None,
    live_sink: EventSink | None = None,
) -> dict:
    started = perf_counter()
    planner_name = (env.get("SQLGUARD_PLANNER") or "demo").casefold()
    # Chỉ planner LLM thật; không bao giờ rơi về planner demo hay mock.
    if planner_name not in {"ollama", "gemini"}:
        raise WebQueryConfigurationError("synthetic_mode_requires_ollama")

    runtime_env = dict(env)
    runtime_env.update(
        {
            "SQLGUARD_PLANNER": planner_name,
            SCHEMA_SOURCE_ENV: "sqlite",
            QUERY_SOURCE_ENV: "sqlite",
            SQLITE_PATH_ENV: str(database_path),
        }
    )
    try:
        planner = await create_planner_for_role(role, runtime_env, policy=policy)
        if not isinstance(planner, LLMPlanner):
            raise WebQueryConfigurationError("synthetic_mode_requires_ollama")
        query_factory = build_query_runtime_factory(role, runtime_env, policy=policy)
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
    planner_class = _WebRepairingPlanner if backend == BUSINESS_QUERY_MODE else _WebRecordingPlanner
    recording_planner = planner_class(planner)
    gate: _WebRecordingGate | None = None
    registry: _WebRecordingRegistry | None = None
    events = InMemoryEventSink()
    sinks: tuple[EventSink, ...] = (events, SQLiteEventStore.from_env(env))
    if live_sink is not None:
        sinks += (live_sink,)
    event_sink = CompositeEventSink(sinks)

    def scope_factory(run_id: str) -> RunScope:
        nonlocal gate, registry
        runtime = query_factory.for_run(run_id, user_id=user_id, question=question)
        gate = _WebRecordingGate(runtime.gate)
        registry = _WebRecordingRegistry(InProcessToolRegistry([runtime.tool]), runtime.tool)
        return RunScope(
            gate,
            registry,
            output_check=runtime.output_check,
            output_check_policy_id=runtime.policy.version if runtime.policy else None,
            output_check_enabled=bool(
                runtime.policy and runtime.policy.canaries_for(runtime.context.role)
            ),
        )

    controller = AgentController(
        planner=recording_planner,
        tools=InProcessToolRegistry([]),
        security_gate=ReadOnlySQLGate(),
        memory=InMemoryMemory(),
        events=event_sink,
        budget=_web_budget(backend, env),
        run_scope_factory=scope_factory,
    )
    state = (await controller.run(AgentRequest(question, run_id=run_id))).state
    decision = gate.last_decision if gate else None
    result = registry.result if registry else None
    gate_status = "ALLOW" if decision and decision.allowed else "BLOCK" if decision else "NOT_RUN"
    succeeded = state.status == RunStatus.SUCCEEDED and result is not None
    removed = list(result.get("removed_columns") or []) if succeeded else []
    if succeeded and removed:
        status = "partial"
        reason = (
            "Trả lời một phần: các cột role này không được đọc đã bị bỏ khỏi truy vấn "
            f"({', '.join(removed)})."
        )
    elif succeeded:
        status = "full"
        reason = (
            "Truy vấn đã qua policy gate và được thực thi trên SQLite tổng hợp."
            if backend == SYNTHETIC_QUERY_MODE
            else f"Truy vấn đã qua policy {policy.version} và được thực thi trên SQLite."
        )
    elif state.status == RunStatus.REFUSED:
        status = "refused"
        reason = _safe_policy_reason(decision)
    else:
        status = "failed"
        reason = _safe_runtime_reason(state.failure_reason)
    small_groups_withheld = bool(succeeded and result.get("small_groups_withheld"))
    if small_groups_withheld:
        reason += (
            f" Các nhóm có dưới {policy.limits.min_group_size} khách hàng/tài khoản đã bị ẩn "
            "để không lộ dữ liệu cá thể."
        )

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
        "backend": backend,
        "role": role,
        "policy_version": policy.version,
        "omitted_fields": removed,
        "small_groups_withheld": small_groups_withheld,
        "question": question,
        "planner": recording_planner.provider,
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
        "events": [_event_payload(event) for event in events.events],
        "duration_ms": (perf_counter() - started) * 1000,
    }
