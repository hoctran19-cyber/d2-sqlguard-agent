"""Chạy câu hỏi ngôn ngữ tự nhiên qua AgentController thật và trả kết quả cho trang Query.

Luồng: câu hỏi -> Planner -> Security Gate -> tool query (database financial) -> kết quả.
Chỉ có planner là bản demo; Controller, Gate và database đều là thành phần thật.
"""

from __future__ import annotations

import asyncio
import json
from dataclasses import asdict
from time import perf_counter

from sqlguard.agent.controller import AgentController
from sqlguard.agent.models import AgentRequest, ExecutionBudget, RunStatus
from sqlguard.mcp.tools import InProcessToolRegistry, ToolError
from sqlguard.memory.store import InMemoryMemory
from sqlguard.observability.events import InMemoryEventSink
from sqlguard.security.gate import ReadOnlySQLGate, SecurityDecision
from sqlguard.web.database import (
    DatabaseUnavailable,
    FinancialDatabase,
    PageResult,
    QueryError,
    QueryTimeout,
)
from sqlguard.web.demo_planner import PLANNER_NAME, DemoFinancialPlanner

# Lý do từ chối của Gate (mã lỗi tiếng Anh) -> câu giải thích tiếng Việt cho người dùng.
GATE_REASONS = {
    "empty_sql": "Câu SQL đang trống.",
    "parse_error": "Không phân tích được câu SQL.",
    "multiple_statements": "Chỉ được chạy đúng một câu lệnh SQL.",
    "not_select": "Chỉ cho phép câu lệnh SELECT chỉ đọc; lệnh ghi/xóa bị chặn.",
    "table_not_allowed": "Câu SQL dùng bảng nằm ngoài danh sách được phép.",
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


async def answer_question(database: FinancialDatabase, question: str) -> dict:
    """Trả về dict cho API /api/query. status: full | partial | refused | failed."""
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
        # Bị từ chối/lỗi thì không có bảng dữ liệu.
        "result": tool.last_result.to_dict() if status == "full" else None,
        # Chỉ gửi tên bước và trạng thái; không có chain-of-thought hay dữ liệu nhạy cảm.
        "events": [
            {"type": e["event_type"], "status": e["status"]} for e in map(asdict, events.events)
        ],
        "duration_ms": (perf_counter() - started) * 1000,
    }
