"""The policy gate and secure tool plugged into the existing AgentController unchanged."""

import asyncio

from tests.security.fakes import SQLiteExecutor

from sqlguard.agent.controller import AgentController, RunScope
from sqlguard.agent.models import AgentRequest, ExecutionBudget, RunStatus
from sqlguard.agent.planning import Plan
from sqlguard.mcp.tools import InProcessToolRegistry, MockQueryTool
from sqlguard.memory.store import InMemoryMemory
from sqlguard.observability.events import InMemoryEventSink
from sqlguard.security.audit import InMemoryAuditSink
from sqlguard.security.gate import PolicySQLGate, ReadOnlySQLGate, SecurityContext
from sqlguard.security.policy import load_default_policy
from sqlguard.security.service import SecureSqlTool, find_leaks

POLICY = load_default_policy()


class FixedPlanner:
    def __init__(self, sql):
        self.sql = sql
        # Bộ đếm giúp xác nhận controller không gọi planner lại sau khi kiểm tra đầu ra lỗi.
        self.create_calls = 0
        self.repair_calls = 0

    async def create_plan(self, question, context):
        self.create_calls += 1
        return Plan(sql=self.sql, summary="fixed")

    async def repair_plan(self, question, context, feedback):
        self.repair_calls += 1
        return Plan(sql=self.sql, summary="repaired")


def run(sql, *, role="sales", controller_gate=None):
    context = SecurityContext(role=role, user_id=f"{role}-demo", run_id="run-1")
    audit = InMemoryAuditSink()
    executor = SQLiteExecutor()
    tool = SecureSqlTool(PolicySQLGate(context, POLICY), executor, audit=audit)
    gate = controller_gate or PolicySQLGate(context, POLICY, audit=audit)
    events = InMemoryEventSink()
    controller = AgentController(
        planner=FixedPlanner(sql),
        tools=InProcessToolRegistry([tool]),
        security_gate=gate,
        memory=InMemoryMemory(),
        events=events,
        budget=ExecutionBudget(max_retries=2),
    )
    result = asyncio.run(controller.run(AgentRequest("question")))
    return result, executor, audit, events


def run_with_output_check(result, output_check):
    """Chạy controller với tool và output_check giả, không cần DB hay LLM thật."""
    planner = FixedPlanner("SELECT 1")
    tool = MockQueryTool(result=result)
    gate = ReadOnlySQLGate()
    events = InMemoryEventSink()
    controller = AgentController(
        planner=planner,
        tools=InProcessToolRegistry([MockQueryTool()]),
        security_gate=gate,
        memory=InMemoryMemory(),
        events=events,
        run_scope_factory=lambda _: RunScope(
            gate, InProcessToolRegistry([tool]), output_check=output_check
        ),
    )
    report = asyncio.run(controller.run(AgentRequest("question")))
    return report, planner, tool, events


def test_allowed_query_reaches_database_only_as_normalized_sql():
    result, executor, audit, _ = run("select full_name from customers where city = 'HCM'")

    assert result.state.status is RunStatus.SUCCEEDED
    assert executor.executed == ["SELECT full_name FROM customers WHERE city = 'HCM' LIMIT 100"]
    assert [(r.phase, r.outcome) for r in audit.records] == [
        ("gate", "allowed"),
        ("execute", "executed"),
    ]
    assert audit.records[0].input_hash == audit.records[1].input_hash


def test_partial_answer_succeeds_without_leaking():
    result, _, audit, _ = run("SELECT full_name, identity_number FROM customers")

    assert result.state.status is RunStatus.SUCCEEDED
    assert "customers.identity_number" in result.state.final_answer
    assert not find_leaks(result.state.final_answer, POLICY, "sales")
    assert audit.records[0].decision_kind == "allow_partial"


def test_policy_denial_refuses_before_tool_and_is_audited():
    result, executor, audit, events = run("SELECT bank_reference FROM payments")

    assert result.state.status is RunStatus.REFUSED
    assert executor.executed == []
    assert [(r.phase, r.outcome) for r in audit.records] == [("gate", "denied")]
    assert all(not hasattr(event, "sql") for event in events.events)


def test_tool_boundary_still_blocks_when_controller_gate_is_weaker():
    # Defense in depth: even with the legacy structural gate in the controller, the execute
    # boundary applies the role policy and the forbidden column never reaches the database.
    result, executor, audit, _ = run(
        "SELECT identity_number FROM customers", controller_gate=ReadOnlySQLGate()
    )

    assert result.state.status is RunStatus.FAILED
    assert result.state.failure_reason == "security_rejection"
    assert result.state.retry_count == 0
    assert executor.executed == []
    assert audit.records[-1].violations == ("column_forbidden",)


def test_operations_role_cannot_reach_payments():
    result, executor, _, _ = run("SELECT amount_vnd FROM payments", role="operations")

    assert result.state.status is RunStatus.REFUSED
    assert executor.executed == []


def test_final_answer_canary_leak_is_blocked_without_retry_or_repair():
    # Tool trả về canary tổng hợp để mô phỏng dữ liệu nhạy cảm lọt vào kết quả đã định dạng.
    canary = "synthetic-canary-5d-controller"
    tool_result = {"rows": [[canary]]}
    leaked_answer = str(tool_result)
    checked_answers = []

    # Checker phát hiện đúng canary nhưng không ghi giá trị đó vào event hay lỗi.
    def output_check(answer):
        checked_answers.append(answer)
        return canary in answer

    result, planner, tool, events = run_with_output_check(tool_result, output_check)
    # Chỉ xét event kiểm tra cuối; nội dung đáp án không được đưa vào event metadata.
    output_events = [
        event for event in events.events if event.event_type == "output_check_completed"
    ]

    # Leak phải làm run thất bại và giữ final_answer ở None để caller không nhận đáp án.
    assert not result.succeeded
    assert result.state.status is RunStatus.FAILED
    assert result.state.final_answer is None
    assert result.state.failure_reason == "canary_leak"
    # Checker nhận đúng chuỗi controller định trả về và ghi nhận trạng thái blocked.
    assert checked_answers == [leaked_answer]
    assert [(event.status, event.error_category) for event in output_events] == [
        ("blocked", "canary_leak")
    ]
    # Kiểm tra output là bước cuối: không được thử SQL lại hoặc nhờ planner sửa vì phát hiện leak.
    assert planner.create_calls == 1 and planner.repair_calls == 0
    assert tool.calls == 1
    assert result.state.sql_attempt_count == 1
    assert result.state.retry_count == 0
    # Canary và toàn bộ câu trả lời bị giữ lại không được xuất hiện trong trạng thái/log sự kiện.
    assert canary not in repr(events.events) + repr(result.state.errors)
    assert leaked_answer not in repr(events.events) + repr(result.state.errors)


def test_output_check_exception_fails_closed_without_leaking_or_retrying():
    # Marker đại diện cho thông tin nội bộ trong exception; controller chỉ được lộ mã lỗi chung.
    marker = "synthetic-output-check-secret-5d"
    safe_result = {"rows": [["safe"]]}

    # Mô phỏng checker hoặc audit của checker phát sinh lỗi chứa thông tin không an toàn.
    def output_check(_answer):
        raise RuntimeError(f"checker failed with {marker}")

    result, planner, tool, events = run_with_output_check(safe_result, output_check)
    # Event phải mô tả checker thất bại bằng category cố định, không mang exception gốc.
    output_events = [
        event for event in events.events if event.event_type == "output_check_completed"
    ]

    # Bất kỳ exception nào tại output_check đều phải chặn đáp án, kể cả khi kết quả trông sạch.
    assert not result.succeeded
    assert result.state.status is RunStatus.FAILED
    assert result.state.final_answer is None
    assert result.state.failure_reason == "output_check_error"
    assert [(event.status, event.error_category) for event in output_events] == [
        ("failed", "output_check_error")
    ]
    # Lỗi kiểm tra không phải lý do để chạy lại truy vấn hay gọi repair planner.
    assert planner.create_calls == 1 and planner.repair_calls == 0
    assert tool.calls == 1
    assert result.state.sql_attempt_count == 1
    assert result.state.retry_count == 0
    # Cả marker lẫn thông điệp exception chi tiết đều phải bị loại khỏi state và event.
    assert marker not in repr(result.state.errors) + repr(events.events)
    assert f"checker failed with {marker}" not in repr(result.state.errors) + repr(events.events)
