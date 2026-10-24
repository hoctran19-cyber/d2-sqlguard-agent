from __future__ import annotations

import argparse
import asyncio
import os
import sys
from collections.abc import Mapping, Sequence
from dataclasses import dataclass, field
from typing import Any

from sqlguard.agent.controller import AgentController, RunScope
from sqlguard.agent.models import AgentRequest, ExecutionBudget
from sqlguard.agent.planning import LLMPlanner, Planner, PlannerConfigError
from sqlguard.agent.postgres_schema import SchemaAdapterError
from sqlguard.agent.runtime import (
    AUDIT_PATH_ENV,
    QUERY_SOURCE_ENV,
    SCHEMA_SOURCE_ENV,
    QueryRuntimeError,
    QueryRuntimeFactory,
    build_query_runtime_factory,
    create_planner_for_role,
)
from sqlguard.mcp.client import sqlite_server_connection
from sqlguard.mcp.tools import InProcessToolRegistry, MockQueryTool, Tool, ToolRegistry
from sqlguard.memory.store import InMemoryMemory
from sqlguard.observability.events import InMemoryEventSink
from sqlguard.security.gate import ReadOnlySQLGate, SecurityDecision, SecurityGate
from sqlguard.security.policy import POLICY_ENV

DEMO_QUESTION = "Show the demo value"
MCP_ENABLED_ENV = "SQLGUARD_MCP_ENABLED"


@dataclass(frozen=True)
class GateCheck:
    sql: str
    allowed: bool
    reason: str


@dataclass
class DemoReport:
    planner: str
    model: str | None
    succeeded: bool
    status: str
    failure_reason: str | None
    final_answer: str | None
    schema_tables: int | None = None
    query_source: str = "mock"
    gate_checks: list[GateCheck] = field(default_factory=list)
    tool_sql: list[str] = field(default_factory=list)
    schema_dialect: str | None = None


class _RecordingGate:
    """Bọc security gate thật: gọi gate để quyết định và ghi lại đúng SQL gate đã kiểm tra.

    Kết quả của gate được trả nguyên vẹn; lớp này không thay đổi hay nới lỏng quyết định nào.
    """

    def __init__(self, gate: SecurityGate, checks: list[GateCheck]) -> None:
        self._gate = gate
        self._checks = checks

    def check(self, sql: str) -> SecurityDecision:
        decision = self._gate.check(sql)
        self._checks.append(GateCheck(sql=sql, allowed=decision.allowed, reason=decision.reason))
        return decision


class _RecordingTools(InProcessToolRegistry):
    """Bọc tool registry: ghi lại đúng SQL thật sự tới tool.

    SQL bị gate từ chối không bao giờ tới đây nên sẽ không xuất hiện trong danh sách.
    """

    def __init__(self, tools: list[Tool], calls: list[str]) -> None:
        super().__init__(tools)
        self._calls = calls

    async def call(self, name: str, arguments: dict[str, Any], *, timeout_seconds: float) -> Any:
        sql = arguments.get("sql")
        if isinstance(sql, str):
            self._calls.append(sql)
        return await super().call(name, arguments, timeout_seconds=timeout_seconds)


class _RecordingRegistry:
    """Ghi lại SQL được gửi tới registry MCP mà không thay đổi kết quả hay lỗi."""

    def __init__(self, registry: ToolRegistry, calls: list[str]) -> None:
        self._registry = registry
        self._calls = calls

    async def call(self, name: str, arguments: dict[str, Any], *, timeout_seconds: float) -> Any:
        sql = arguments.get("sql")
        if isinstance(sql, str):
            self._calls.append(sql)
        return await self._registry.call(name, arguments, timeout_seconds=timeout_seconds)


def _mcp_enabled(env: Mapping[str, str]) -> bool:
    raw = env.get(MCP_ENABLED_ENV)
    if raw is None or raw.casefold() == "false":
        return False
    if raw.casefold() == "true":
        return True
    raise QueryRuntimeError("mcp_invalid_config")


def budget_from_env(env: Mapping[str, str] | None = None) -> ExecutionBudget:
    """Tạo budget cho demo; ``SQLGUARD_RUN_TIMEOUT_SECONDS`` ghi đè giới hạn mặc định 60 giây."""
    env = os.environ if env is None else env
    raw = env.get("SQLGUARD_RUN_TIMEOUT_SECONDS")
    if not raw:
        return ExecutionBudget()
    try:
        return ExecutionBudget(run_timeout_seconds=float(raw))
    except ValueError:
        raise ValueError("SQLGUARD_RUN_TIMEOUT_SECONDS must be a positive number") from None


# Trả về (tên planner, tên model) để hiển thị; model chỉ có với planner LLM.
def _planner_label(planner: Planner) -> tuple[str, str | None]:
    if isinstance(planner, LLMPlanner):
        return planner.provider, planner.model
    return "demo", None


# Đếm số bảng trong schema planner đang giữ; chỉ in số lượng, không in metadata nhạy cảm.
def _schema_table_count(planner: Planner) -> int | None:
    schema = planner.schema_context if isinstance(planner, LLMPlanner) else None
    return len(schema.tables) if schema else None


def _schema_dialect(planner: Planner) -> str | None:
    schema = planner.schema_context if isinstance(planner, LLMPlanner) else None
    return schema.dialect if schema else None


async def run_demo_report(
    planner: Planner | None = None,
    *,
    question: str = DEMO_QUESTION,
    gate: SecurityGate | None = None,
    tool: MockQueryTool | None = None,
    budget: ExecutionBudget | None = None,
    query_factory: QueryRuntimeFactory | None = None,
) -> DemoReport:
    env = dict(os.environ)
    # SQLGUARD_ROLE do người vận hành đặt trong môi trường chạy, KHÔNG lấy từ câu hỏi hay LLM.
    # Cùng một role này được dùng cho schema, gate, SecureSqlTool và executor của lần chạy.
    role = env.get("SQLGUARD_ROLE")
    use_mcp = _mcp_enabled(env)
    if use_mcp:
        if (env.get(QUERY_SOURCE_ENV) or "mock").casefold() != "sqlite":
            raise QueryRuntimeError("mcp_requires_sqlite")
        if gate is not None or tool is not None:
            raise QueryRuntimeError("mcp_invalid_config")
        if not role or not role.strip():
            raise QueryRuntimeError("query_role_missing")
        database = env.get("SQLGUARD_SQLITE_PATH")
        if not database or not database.strip():
            raise QueryRuntimeError("query_sqlite_path_missing")
        database_path = os.path.expanduser(database)
        if not os.path.isfile(database_path):
            raise QueryRuntimeError("query_sqlite_db_missing")
        env["SQLGUARD_SQLITE_PATH"] = database_path
    # Dựng cấu hình truy vấn TRƯỚC planner để lỗi cấu hình dừng sớm (chưa nạp schema/gọi LLM).
    # Nếu bên gọi tiêm gate/tool riêng (test) thì giữ nguyên đường đi cũ.
    if query_factory is None and gate is None and tool is None:
        query_factory = build_query_runtime_factory(role, env)
    if use_mcp and (
        query_factory is None
        or query_factory.source != "sqlite"
        or query_factory.role != role.strip().casefold()
    ):
        raise QueryRuntimeError("mcp_invalid_config")
    if (
        planner is None
        and (env.get("SQLGUARD_PLANNER") or "demo").casefold() in {"ollama", "gemini"}
        and query_factory is not None
        and query_factory.source == "sqlite"
        and (env.get(SCHEMA_SOURCE_ENV) or "none").casefold() != "sqlite"
    ):
        raise SchemaAdapterError("schema_sqlite_source_required")
    planner = planner or await create_planner_for_role(role)
    name, model = _planner_label(planner)
    checks: list[GateCheck] = []
    tool_sql: list[str] = []

    # Controller dùng gate thật và tool mock; hai lớp bọc chỉ để ghi lại SQL phục vụ báo cáo.
    # Chế độ database dùng SecureSqlTool + PolicySQLGate; chế độ mock dùng MockQueryTool như cũ.
    # Không bao giờ chuyển sang mock khi chế độ database gặp lỗi (lỗi đã được ném ở trên).
    def make_scope_factory(registry: ToolRegistry | None = None):
        if query_factory is None:
            return None

        # Gate/tool scope vẫn gắn với run_id của controller; MCP chỉ thay registry phía thực thi.
        def scope_factory(run_id: str) -> RunScope:
            built = query_factory.for_run(run_id)
            scoped_tools: ToolRegistry = (
                _RecordingRegistry(registry, tool_sql)
                if registry is not None
                else _RecordingTools([built.tool], tool_sql)
            )
            return RunScope(
                _RecordingGate(built.gate, checks),
                scoped_tools,
                output_check=built.output_check,
            )

        return scope_factory

    def make_controller(scope_factory, registry: ToolRegistry | None = None) -> AgentController:
        # PostgreSQL và mock giữ registry hiện tại; chỉ nhánh MCP tiêm registry từ xa vào
        # cùng RunScope với gate và bước kiểm tra đầu ra.
        query_tool: Tool = tool or MockQueryTool()
        query_gate: SecurityGate = gate or ReadOnlySQLGate()
        return AgentController(
            run_scope_factory=scope_factory,
            planner=planner,
            tools=(
                _RecordingRegistry(registry, tool_sql)
                if registry is not None
                else _RecordingTools([query_tool], tool_sql)
            ),
            security_gate=_RecordingGate(query_gate, checks),
            memory=InMemoryMemory(),
            events=InMemoryEventSink(),
            budget=budget or budget_from_env(),
        )

    if use_mcp:
        extra_env = {key: env[key] for key in (AUDIT_PATH_ENV, POLICY_ENV) if env.get(key)} or None
        connection = sqlite_server_connection(
            database_path,
            role or "",
            extra_env=extra_env,
        )
        try:
            async with connection:
                try:
                    registry = await connection.registry()
                except Exception:
                    raise QueryRuntimeError("mcp_discovery_failed") from None
                controller = make_controller(make_scope_factory(registry), registry)
                result = await controller.run(AgentRequest(question=question))
        except QueryRuntimeError:
            raise
        except Exception:
            # Không truyền thông báo transport/SDK lên output hay log của ứng dụng.
            raise QueryRuntimeError("mcp_connection_failed") from None
    else:
        # Đường PostgreSQL, SQLite trực tiếp và mock giữ nguyên registry hiện tại.
        controller = make_controller(make_scope_factory())
        result = await controller.run(AgentRequest(question=question))
    state = result.state
    return DemoReport(
        planner=name,
        model=model,
        succeeded=result.succeeded,
        status=state.status.value,
        failure_reason=state.failure_reason,
        final_answer=state.final_answer,
        schema_tables=_schema_table_count(planner),
        query_source="mcp" if use_mcp else (query_factory.source if query_factory else "mock"),
        gate_checks=checks,
        tool_sql=tool_sql,
        schema_dialect=_schema_dialect(planner),
    )


def format_report(report: DemoReport) -> str:
    lines = [f"planner: {report.planner}"]
    if report.model:
        lines.append(f"model: {report.model}")
    if report.schema_tables is not None:
        lines.append(f"schema: loaded from {report.schema_dialect} ({report.schema_tables} tables)")
    real = report.query_source != "mock"
    if report.query_source == "postgres":
        lines.append("tool: SecureSqlTool + PostgresExecutor (real PostgreSQL, read-only)")
    elif report.query_source == "sqlite":
        lines.append("tool: SecureSqlTool + SQLiteExecutor (local SQLite, read-only)")
    elif report.query_source == "mcp":
        lines.append("tool: MCP STDIO + SQLGuard SQLite server (read-only)")
    else:
        lines.append("tool: MockQueryTool (mock; no database is queried)")
    if not report.gate_checks:
        lines.append("proposed_sql: (none; the planner produced no SQL for the gate)")
    for number, check in enumerate(report.gate_checks, start=1):
        lines.append(f"proposed_sql[{number}]: {check.sql}")
        verdict = "allowed" if check.allowed else "rejected"
        lines.append(f"security_gate[{number}]: {verdict} ({check.reason})")
    for number, sql in enumerate(report.tool_sql, start=1):
        lines.append(f"{'tool_input_sql' if real else 'mock_tool_sql'}[{number}]: {sql}")
    if report.succeeded:
        lines.append(f"{'result' if real else 'mock_result'}: {report.final_answer}")
    else:
        lines.append(f"status: {report.status}")
        lines.append(f"failure_reason: {report.failure_reason}")
    return "\n".join(lines)


async def run_demo(question: str = DEMO_QUESTION) -> str:
    report = await run_demo_report(question=question)
    if not report.succeeded:
        raise RuntimeError(report.failure_reason)
    return report.final_answer or ""


def main(argv: Sequence[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Run the SQLGuard Text-to-SQL demo.")
    parser.add_argument(
        "--question",
        default=DEMO_QUESTION,
        help="natural-language question to send to the configured planner",
    )
    args = parser.parse_args(argv)
    try:
        report = asyncio.run(run_demo_report(question=args.question))
    except (PlannerConfigError, ValueError) as error:
        print(f"configuration_error: {error}", file=sys.stderr)
        return 2
    except QueryRuntimeError as error:
        print(f"query_config_error: {error.category}", file=sys.stderr)
        return 2
    except SchemaAdapterError as error:
        print(f"schema_error: {error.category}", file=sys.stderr)
        return 2
    print(format_report(report))
    return 0 if report.succeeded else 1


if __name__ == "__main__":
    sys.exit(main())
