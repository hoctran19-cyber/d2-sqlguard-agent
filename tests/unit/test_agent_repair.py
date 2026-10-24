import asyncio

import pytest
from tests.unit.test_agent_runtime_query import PG_ENV, RecordingExecutor

from sqlguard.agent import planning
from sqlguard.agent.controller import AgentController, RunScope
from sqlguard.agent.models import AgentRequest, ExecutionBudget, RunStatus
from sqlguard.agent.planning import DemoPlanner, OllamaPlanner, Plan, RepairFeedback
from sqlguard.agent.runtime import build_query_runtime_factory
from sqlguard.mcp.tools import InProcessToolRegistry, MockQueryTool
from sqlguard.memory.store import InMemoryMemory
from sqlguard.observability.events import InMemoryEventSink, LiveEvent
from sqlguard.security.audit import InMemoryAuditSink
from sqlguard.security.gate import PolicySQLGate, ReadOnlySQLGate, SecurityContext
from sqlguard.security.policy import load_default_policy
from sqlguard.security.service import SecureSqlTool

GOOD_SQL = "SELECT order_id FROM orders ORDER BY order_id LIMIT 2"
# Cột không tồn tại: gate coi là denial CÓ THỂ sửa.
REPAIRABLE_SQL = "SELECT no_such_column FROM orders"
# Câu lệnh ghi: denial KHÔNG thể sửa.
TERMINAL_SQL = "DELETE FROM orders"
POLICY = load_default_policy()


class RecordingLiveEventSink:
    def __init__(self):
        self.events: list[LiveEvent] = []

    def emit(self, event):
        self.events.append(event)


# Planner giả: trả lần lượt các SQL đã định sẵn; ghi lại mọi feedback nhận được.
class ScriptedRepairPlanner:
    def __init__(self, first, repairs, error=None, delay=0.0):
        self.first = first
        self.repairs = list(repairs)
        self.error = error
        self.delay = delay
        self.create_calls = 0
        self.feedback: list[RepairFeedback] = []

    async def create_plan(self, question, context):
        self.create_calls += 1
        return Plan(sql=self.first, summary="first")

    async def repair_plan(self, question, context, feedback):
        self.feedback.append(feedback)
        if self.delay:
            await asyncio.sleep(self.delay)
        if self.error:
            raise self.error
        return Plan(
            sql=self.repairs.pop(0) if len(self.repairs) > 1 else self.repairs[0], summary="r"
        )


# Planner không hỗ trợ repair (giống DemoPlanner): chỉ có create_plan.
class PlainPlanner:
    def __init__(self, sql):
        self.sql = sql
        self.calls = 0

    async def create_plan(self, question, context):
        self.calls += 1
        return Plan(sql=self.sql, summary="plain")


# Gate bọc ngoài, ghi lại mọi SQL được kiểm tra.
class RecordingGate:
    def __init__(self, inner):
        self.inner = inner
        self.checked: list[str] = []
        self.decisions = []

    def check(self, sql):
        self.checked.append(sql)
        decision = self.inner.check(sql)
        self.decisions.append(decision)
        return decision


def strict_stack(role="sales", executor=None, audit=None, run_id="run-1"):
    context = SecurityContext(role=role, user_id="u", run_id=run_id, request_mode="nl")
    executor = executor or RecordingExecutor(("order_id",), [(1,)])
    tool = SecureSqlTool(PolicySQLGate(context, POLICY), executor, audit=audit)
    return PolicySQLGate(context, POLICY, audit=audit), tool, executor


def controller(planner, gate, tool, budget=None, events=None):
    return AgentController(
        planner=planner,
        tools=InProcessToolRegistry([tool]),
        security_gate=gate,
        memory=InMemoryMemory(),
        events=events or InMemoryEventSink(),
        budget=budget or ExecutionBudget(),
    )


def run(ctrl):
    return asyncio.run(ctrl.run(AgentRequest("question")))


def test_repairable_denial_then_valid_sql_succeeds():
    gate, tool, executor = strict_stack()
    planner = ScriptedRepairPlanner(REPAIRABLE_SQL, [GOOD_SQL])
    events = RecordingLiveEventSink()
    result = run(controller(planner, RecordingGate(gate), tool, events=events))

    assert result.succeeded
    assert planner.create_calls == 1 and len(planner.feedback) == 1
    assert result.state.llm_call_count == 2
    assert result.state.sql_attempt_count == 2
    feedback = planner.feedback[0]
    assert feedback.previous_sql == REPAIRABLE_SQL
    assert feedback.violation_codes
    # Executor chỉ nhận SQL đã chuẩn hóa của câu đã sửa; SQL bị từ chối không tới đây.
    assert len(executor.calls) == 1
    assert "no_such_column" not in executor.calls[0]
    types = [event.event_type for event in events.events]
    assert "repair_started" in types and "repair_completed" in types
    assert {event.run_id for event in events.events} == {result.state.run_id}
    repair_events = [event for event in events.events if event.event_type.startswith("repair_")]
    assert all(event.attempt_id == "sql-2" for event in repair_events)
    assert all(event.related_attempt_id == "sql-1" for event in repair_events)
    security_attempts = [
        (event.attempt_id, event.status)
        for event in events.events
        if event.event_type == "security_check_completed"
    ]
    assert security_attempts == [("sql-1", "denied"), ("sql-2", "allowed")]
    assert any(
        event.event_type == "tool_call_started" and event.attempt_id == "sql-2"
        for event in events.events
    )


def test_repair_events_are_metadata_only():
    gate, tool, _ = strict_stack()
    events = InMemoryEventSink()
    planner = ScriptedRepairPlanner(REPAIRABLE_SQL, [GOOD_SQL])
    run(controller(planner, gate, tool, events=events))
    dumped = repr(events.events)
    assert "no_such_column" not in dumped and "question" not in dumped
    assert "order_id" not in dumped


def test_non_repairable_denial_never_repairs_or_executes():
    gate, tool, executor = strict_stack()
    planner = ScriptedRepairPlanner(TERMINAL_SQL, [GOOD_SQL])
    result = run(controller(planner, gate, tool))
    assert result.state.status == RunStatus.REFUSED
    assert result.state.failure_reason == "security_rejection"
    assert planner.feedback == []
    assert planner.create_calls == 1 and result.state.llm_call_count == 1
    assert executor.calls == []


def test_planner_without_repair_support_keeps_terminal_behavior():
    gate, tool, executor = strict_stack()
    planner = PlainPlanner(REPAIRABLE_SQL)
    result = run(controller(planner, gate, tool))
    assert result.state.status == RunStatus.REFUSED
    assert planner.calls == 1 and executor.calls == []


def test_demo_planner_and_mock_flow_unchanged():
    result = run(controller(DemoPlanner(), ReadOnlySQLGate(), MockQueryTool()))
    assert result.succeeded and result.state.llm_call_count == 1
    assert not hasattr(DemoPlanner(), "repair_plan")


def test_repeated_repairable_denials_stop_at_planner_call_budget():
    gate, tool, executor = strict_stack()
    planner = ScriptedRepairPlanner(REPAIRABLE_SQL, [REPAIRABLE_SQL])
    budget = ExecutionBudget(max_llm_calls=3, max_sql_attempts=10)
    result = run(controller(planner, gate, tool, budget))
    assert result.state.status == RunStatus.BUDGET_EXHAUSTED
    assert result.state.failure_reason == "planner_call_budget_exhausted"
    assert result.state.llm_call_count == 3
    assert result.state.sql_attempt_count == 3
    assert executor.calls == []


def test_repeated_repairable_denials_stop_at_sql_attempt_budget():
    gate, tool, executor = strict_stack()
    planner = ScriptedRepairPlanner(REPAIRABLE_SQL, [REPAIRABLE_SQL])
    budget = ExecutionBudget(max_llm_calls=20, max_sql_attempts=2)
    result = run(controller(planner, gate, tool, budget))
    assert result.state.status == RunStatus.BUDGET_EXHAUSTED
    assert result.state.failure_reason == "sql_attempt_budget_exhausted"
    assert result.state.sql_attempt_count == 2
    assert result.state.llm_call_count == 2
    assert executor.calls == []


def test_every_repaired_sql_is_checked_before_execution():
    gate, tool, executor = strict_stack()
    recording = RecordingGate(gate)
    # Lần sửa đầu vẫn sai (repairable), lần sau mới đúng.
    planner = ScriptedRepairPlanner(REPAIRABLE_SQL, ["SELECT other_bad FROM orders", GOOD_SQL])
    result = run(controller(planner, recording, tool))
    assert result.succeeded
    assert recording.checked == [REPAIRABLE_SQL, "SELECT other_bad FROM orders", GOOD_SQL]
    assert len(executor.calls) == 1
    assert result.state.sql_attempt_count == 3


def test_repaired_sql_passes_gate_again_before_execution():
    gate, tool, executor = strict_stack()
    recording = RecordingGate(gate)
    planner = ScriptedRepairPlanner(REPAIRABLE_SQL, [GOOD_SQL])
    result = run(controller(planner, recording, tool))

    assert result.succeeded
    assert recording.checked == [REPAIRABLE_SQL, GOOD_SQL]
    assert [decision.repairable for decision in recording.decisions] == [True, False]
    assert [decision.allowed for decision in recording.decisions] == [False, True]
    assert len(planner.feedback) == 1
    assert planner.feedback[0].previous_sql == REPAIRABLE_SQL
    assert result.state.sql_attempt_count == 2 and result.state.llm_call_count == 2
    assert len(executor.calls) == 1
    assert executor.calls[0] == recording.decisions[1].normalized_sql
    assert REPAIRABLE_SQL not in executor.calls[0]


def test_repair_to_forbidden_sql_is_refused_without_execution():
    gate, tool, executor = strict_stack()
    planner = ScriptedRepairPlanner(REPAIRABLE_SQL, [TERMINAL_SQL])
    result = run(controller(planner, gate, tool))
    assert result.state.status == RunStatus.REFUSED
    assert len(planner.feedback) == 1
    assert executor.calls == []


def test_tool_level_repairable_rejection_goes_through_repair():
    _, tool, executor = strict_stack()
    weak = RecordingGate(ReadOnlySQLGate())
    planner = ScriptedRepairPlanner(REPAIRABLE_SQL, [GOOD_SQL])
    result = run(controller(planner, weak, tool))
    assert result.succeeded
    assert len(planner.feedback) == 1
    # Sau repair, SQL mới vẫn phải qua gate của controller trước khi tới tool.
    assert weak.checked == [REPAIRABLE_SQL, GOOD_SQL]
    assert len(executor.calls) == 1


def test_tool_level_non_repairable_rejection_cannot_bypass_checks():
    _, tool, executor = strict_stack()
    planner = ScriptedRepairPlanner("SELECT phone_number FROM customers", [GOOD_SQL])
    result = run(controller(planner, ReadOnlySQLGate(), tool))
    # F1: kết thúc REFUSED như khi gate của controller từ chối.
    assert result.state.status == RunStatus.REFUSED
    assert result.state.failure_reason == "security_rejection"
    assert planner.feedback == []
    assert executor.calls == []


def test_tool_level_repair_is_bounded_by_budget():
    _, tool, executor = strict_stack()
    planner = ScriptedRepairPlanner(REPAIRABLE_SQL, [REPAIRABLE_SQL])
    budget = ExecutionBudget(max_llm_calls=3, max_tool_calls=8)
    result = run(controller(planner, ReadOnlySQLGate(), tool, budget))
    assert result.state.status == RunStatus.BUDGET_EXHAUSTED
    assert result.state.llm_call_count == 3
    assert executor.calls == []


def test_tool_call_budget_stops_tool_level_repair():
    _, tool, executor = strict_stack()
    planner = ScriptedRepairPlanner(REPAIRABLE_SQL, [REPAIRABLE_SQL])
    budget = ExecutionBudget(max_tool_calls=1, max_llm_calls=10, max_sql_attempts=10)
    result = run(controller(planner, ReadOnlySQLGate(), tool, budget))
    assert result.state.failure_reason == "tool_call_budget_exhausted"
    assert result.state.tool_call_count == 1
    assert executor.calls == []


def test_planner_failure_during_repair_fails_safely_without_leaks():
    gate, tool, executor = strict_stack()
    planner = ScriptedRepairPlanner(
        REPAIRABLE_SQL, [GOOD_SQL], error=RuntimeError("postgresql://user:pw@host/db")
    )
    events = InMemoryEventSink()
    result = run(controller(planner, gate, tool, events=events))
    assert result.state.status == RunStatus.FAILED
    assert result.state.failure_reason == "planner_error"
    assert executor.calls == []
    dumped = repr(events.events) + repr(result.state.errors) + str(result.state.failure_reason)
    assert "postgresql" not in dumped and "pw" not in dumped
    assert any(e.event_type == "repair_completed" and e.status == "failed" for e in events.events)


def test_malformed_repair_plan_fails_safely():
    gate, tool, executor = strict_stack()

    class BadPlanner(ScriptedRepairPlanner):
        async def repair_plan(self, question, context, feedback):
            return object()

    result = run(controller(BadPlanner(REPAIRABLE_SQL, []), gate, tool))
    assert result.state.failure_reason == "planner_error"
    assert executor.calls == []


def test_slow_repair_respects_run_timeout():
    gate, tool, executor = strict_stack()
    planner = ScriptedRepairPlanner(REPAIRABLE_SQL, [GOOD_SQL], delay=1.0)
    result = run(controller(planner, gate, tool, ExecutionBudget(run_timeout_seconds=0.05)))
    assert result.state.status == RunStatus.TIMED_OUT
    assert executor.calls == []


def test_audit_failure_stays_fail_closed_and_is_not_repaired():
    class BrokenAudit:
        def record(self, record):
            raise OSError("disk full")

    gate, tool, executor = strict_stack(audit=BrokenAudit())
    planner = ScriptedRepairPlanner(REPAIRABLE_SQL, [GOOD_SQL])
    result = run(controller(planner, gate, tool))
    assert not result.succeeded
    assert planner.feedback == []
    assert executor.calls == []


def test_tool_canary_leak_after_execution_is_terminal_and_not_repaired():
    canary = POLICY.canaries_for("sales")[0].value
    executor = RecordingExecutor(("note",), [(canary,)])
    context = SecurityContext(role="sales", user_id="u", run_id="run-1", request_mode="nl")
    tool = SecureSqlTool(PolicySQLGate(context, POLICY), executor)
    # Gate của controller cho phép SQL; canary chỉ bị phát hiện sau khi executor đã chạy.
    gate = RecordingGate(PolicySQLGate(context, POLICY))
    planner = ScriptedRepairPlanner(GOOD_SQL, [GOOD_SQL])
    events = InMemoryEventSink()
    result = run(controller(planner, gate, tool, events=events))
    assert result.state.status == RunStatus.FAILED
    assert result.state.failure_reason == "canary_leak"
    assert result.state.final_answer is None
    assert planner.feedback == []
    assert result.state.llm_call_count == 1
    # Chỉ một lần thực thi duy nhất, không chạy thêm truy vấn nào sau khi bị giữ kết quả.
    assert len(executor.calls) == 1
    assert gate.checked == [GOOD_SQL]
    assert canary not in repr(events.events) + repr(result.state.errors)
    assert not any(e.event_type.startswith("repair") for e in events.events)


def test_tool_audit_failure_is_terminal_and_returns_no_result():
    class BrokenAudit:
        def record(self, record):
            raise OSError("disk full: secret-path")

    executor = RecordingExecutor(("order_id",), [("secret-row-value",)])
    context = SecurityContext(role="sales", user_id="u", run_id="run-1", request_mode="nl")
    # Chỉ audit sink của tool hỏng; gate của controller không có audit và cho phép SQL.
    tool = SecureSqlTool(PolicySQLGate(context, POLICY), executor, audit=BrokenAudit())
    gate = RecordingGate(PolicySQLGate(context, POLICY))
    planner = ScriptedRepairPlanner(GOOD_SQL, [GOOD_SQL])
    events = InMemoryEventSink()
    result = run(controller(planner, gate, tool, events=events))
    assert not result.succeeded
    assert result.state.final_answer is None
    assert planner.feedback == []
    assert result.state.llm_call_count == 1
    assert len(executor.calls) <= 1
    assert gate.checked == [GOOD_SQL]
    dumped = repr(events.events) + repr(result.state.errors) + str(result.state.failure_reason)
    assert "secret" not in dumped
    assert not any(e.event_type.startswith("repair") for e in events.events)


def test_concurrent_repairing_runs_keep_run_ids_and_roles_isolated():
    audit = InMemoryAuditSink()
    exec_a = RecordingExecutor(("a",), [(1,)])
    exec_b = RecordingExecutor(("a",), [(1,)])
    factories = {
        "sales": build_query_runtime_factory("sales", PG_ENV, executor=exec_a, audit=audit),
        "finance": build_query_runtime_factory("finance", PG_ENV, executor=exec_b, audit=audit),
    }

    def make(role):
        def scope(run_id):
            built = factories[role].for_run(run_id)
            return RunScope(built.gate, InProcessToolRegistry([built.tool]))

        return AgentController(
            planner=ScriptedRepairPlanner(REPAIRABLE_SQL, [GOOD_SQL]),
            tools=InProcessToolRegistry([MockQueryTool()]),
            security_gate=ReadOnlySQLGate(),
            memory=InMemoryMemory(),
            events=InMemoryEventSink(),
            run_scope_factory=scope,
        )

    async def both():
        return await asyncio.gather(
            make("sales").run(AgentRequest("1")), make("finance").run(AgentRequest("2"))
        )

    r1, r2 = asyncio.run(both())
    assert r1.succeeded and r2.succeeded
    assert r1.state.run_id != r2.state.run_id
    assert exec_a.roles == ["sales"] and exec_b.roles == ["finance"]
    roles_by_run = {}
    for record in audit.records:
        roles_by_run.setdefault(record.run_id, set()).add(record.role)
    assert roles_by_run == {r1.state.run_id: {"sales"}, r2.state.run_id: {"finance"}}


# --- OllamaPlanner.repair_plan: payload không cần server Ollama ---


def test_ollama_repair_payload_wraps_untrusted_feedback(monkeypatch):
    sent = []

    def fake_post(self, payload):
        sent.append(payload)
        return b'{"message": {"content": "{\\"sql\\": \\"SELECT 1\\", \\"summary\\": \\"s\\"}"}}'

    monkeypatch.setattr(OllamaPlanner, "_post", fake_post)
    planner = OllamaPlanner()
    feedback = RepairFeedback("SELECT bad FROM t", ("column_unknown",), "Repairable: fix it")
    plan = asyncio.run(planner.repair_plan("q", (), feedback))
    assert plan.sql == "SELECT 1"
    user = sent[0]["messages"][1]["content"]
    assert "<<untrusted:previous_sql:" in user and "SELECT bad FROM t" in user
    assert "<<untrusted:security_denial:" in user
    # create_plan không kèm feedback nên payload không có phần từ chối.
    normal = planner._build_payload("q", ())
    assert "previous_sql" not in normal["messages"][1]["content"]
    assert planning.RepairFeedback is RepairFeedback


@pytest.mark.parametrize("budget_llm", [1])
def test_zero_extra_planner_calls_when_budget_is_one(budget_llm):
    gate, tool, executor = strict_stack()
    planner = ScriptedRepairPlanner(REPAIRABLE_SQL, [GOOD_SQL])
    result = run(controller(planner, gate, tool, ExecutionBudget(max_llm_calls=budget_llm)))
    assert result.state.failure_reason == "planner_call_budget_exhausted"
    assert planner.feedback == [] and executor.calls == []
