from __future__ import annotations

import asyncio
import os
import sys
from collections.abc import Mapping
from dataclasses import dataclass, field
from typing import Any

from sqlguard.agent.controller import AgentController, RunScope
from sqlguard.agent.models import AgentRequest, ExecutionBudget
from sqlguard.agent.planning import OllamaPlanner, Planner, PlannerConfigError
from sqlguard.agent.postgres_schema import SchemaAdapterError
from sqlguard.agent.runtime import (
    QueryRuntimeError,
    QueryRuntimeFactory,
    build_query_runtime_factory,
    create_planner_for_role,
)
from sqlguard.mcp.tools import InProcessToolRegistry, MockQueryTool, Tool
from sqlguard.memory.store import InMemoryMemory
from sqlguard.observability.events import InMemoryEventSink
from sqlguard.security.gate import ReadOnlySQLGate, SecurityDecision, SecurityGate

DEMO_QUESTION = "Show the demo value"


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


# Trả về (tên planner, tên model) để hiển thị; model chỉ có với Ollama.
def _planner_label(planner: Planner) -> tuple[str, str | None]:
    if isinstance(planner, OllamaPlanner):
        return "ollama", planner.model
    return "demo", None


# Đếm số bảng trong schema planner đang giữ; chỉ in số lượng, không in metadata nhạy cảm.
def _schema_table_count(planner: Planner) -> int | None:
    schema = planner.schema_context if isinstance(planner, OllamaPlanner) else None
    return len(schema.tables) if schema else None


async def run_demo_report(
    planner: Planner | None = None,
    *,
    gate: SecurityGate | None = None,
    tool: MockQueryTool | None = None,
    budget: ExecutionBudget | None = None,
    query_factory: QueryRuntimeFactory | None = None,
) -> DemoReport:
    # SQLGUARD_ROLE do người vận hành đặt trong môi trường chạy, KHÔNG lấy từ câu hỏi hay LLM.
    # Cùng một role này được dùng cho schema, gate, SecureSqlTool và executor của lần chạy.
    role = os.environ.get("SQLGUARD_ROLE")
    # Dựng cấu hình truy vấn TRƯỚC planner để lỗi cấu hình dừng sớm (chưa nạp schema/gọi LLM).
    # Nếu bên gọi tiêm gate/tool riêng (test) thì giữ nguyên đường đi cũ.
    if query_factory is None and gate is None and tool is None:
        query_factory = build_query_runtime_factory(role)
    planner = planner or await create_planner_for_role(role)
    name, model = _planner_label(planner)
    checks: list[GateCheck] = []
    tool_sql: list[str] = []
    # Controller dùng gate thật và tool mock; hai lớp bọc chỉ để ghi lại SQL phục vụ báo cáo.
    # Chế độ postgres: SecureSqlTool + PolicySQLGate thật; chế độ mock: MockQueryTool như cũ.
    # Không bao giờ chuyển từ postgres sang mock khi có lỗi (lỗi đã được ném ở trên).
    real = query_factory is not None
    scope_factory = None
    if query_factory is not None:
        # Gate/tool được dựng theo run_id của controller để audit khớp với run.
        def scope_factory(run_id: str) -> RunScope:
            built = query_factory.for_run(run_id)
            return RunScope(
                _RecordingGate(built.gate, checks),
                _RecordingTools([built.tool], tool_sql),
                # Kiểm tra rò rỉ câu trả lời cuối bằng role tin cậy của run (chỉ ở chế độ postgres).
                output_check=built.output_check,
            )

    # Đường postgres chỉ đi qua scope_factory (gate/tool theo run_id); không nhận runtime dựng sẵn.
    query_tool: Tool = tool or MockQueryTool()
    query_gate: SecurityGate = gate or ReadOnlySQLGate()
    controller = AgentController(
        run_scope_factory=scope_factory,
        planner=planner,
        tools=_RecordingTools([query_tool], tool_sql),
        security_gate=_RecordingGate(query_gate, checks),
        memory=InMemoryMemory(),
        events=InMemoryEventSink(),
        budget=budget or budget_from_env(),
    )
    result = await controller.run(AgentRequest(question=DEMO_QUESTION))
    state = result.state
    return DemoReport(
        planner=name,
        model=model,
        succeeded=result.succeeded,
        status=state.status.value,
        failure_reason=state.failure_reason,
        final_answer=state.final_answer,
        schema_tables=_schema_table_count(planner),
        query_source="postgres" if real else "mock",
        gate_checks=checks,
        tool_sql=tool_sql,
    )


def format_report(report: DemoReport) -> str:
    lines = [f"planner: {report.planner}"]
    if report.model:
        lines.append(f"model: {report.model}")
    if report.schema_tables is not None:
        lines.append(f"schema: loaded from postgres ({report.schema_tables} tables)")
    real = report.query_source == "postgres"
    if real:
        lines.append("tool: SecureSqlTool + PostgresExecutor (real PostgreSQL, read-only)")
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


async def run_demo() -> str:
    report = await run_demo_report()
    if not report.succeeded:
        raise RuntimeError(report.failure_reason)
    return report.final_answer or ""


def main() -> int:
    try:
        report = asyncio.run(run_demo_report())
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
