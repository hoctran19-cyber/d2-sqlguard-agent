import asyncio

from tests.conftest import make_controller

from sqlguard.agent.models import AgentRequest, ExecutionBudget, RunStatus
from sqlguard.mcp.tools import MockQueryTool, ToolError
from sqlguard.memory.store import InMemoryMemory
from sqlguard.observability.events import InMemoryEventSink

CANONICAL_TERMINAL_EVENTS = {
    "run_completed",
    "run_refused",
    "run_timed_out",
    "budget_exhausted",
    "run_failed",
}


def assert_single_terminal_event(events, expected_type, status, error_category=None):
    terminal_events = [event for event in events if event.event_type in CANONICAL_TERMINAL_EVENTS]

    assert len(terminal_events) == 1
    assert terminal_events[0].event_type == expected_type
    assert terminal_events[0].status == status
    assert terminal_events[0].error_category == error_category
    assert terminal_events[0].duration_ms is not None


def test_valid_request_completes_demo_flow():
    events = InMemoryEventSink()
    result = asyncio.run(make_controller(events=events).run(AgentRequest("Show the demo")))

    assert result.succeeded
    assert result.state.status == RunStatus.SUCCEEDED
    assert result.state.final_answer == "demo_value=1"
    assert result.state.llm_call_count == 1
    assert result.state.tool_call_count == 1
    assert result.state.sql_attempt_count == 1
    assert result.state.current_step == "completed"
    assert_single_terminal_event(events.events, "run_completed", "succeeded")


def test_tool_error_is_reported_and_retried_within_budget():
    tool = MockQueryTool(failure=ToolError("temporary"))
    memory = InMemoryMemory()
    result = asyncio.run(
        make_controller(tool=tool, memory=memory, budget=ExecutionBudget(max_retries=1)).run(
            AgentRequest("Question")
        )
    )

    assert result.state.status == RunStatus.FAILED
    assert result.state.failure_reason == "tool_error"
    assert result.state.retry_count == 1
    assert tool.calls == 2
    assert memory.get(result.state.run_id, "retry") == ("1",)
    assert result.state.sql_attempt_count == 2


def test_recoverable_tool_error_can_succeed_on_retry():
    class FlakyTool(MockQueryTool):
        async def call(self, arguments, *, timeout_seconds):
            self.calls += 1
            if self.calls == 1:
                raise ToolError("temporary")
            return "recovered"

    tool = FlakyTool()
    result = asyncio.run(
        make_controller(tool=tool, budget=ExecutionBudget(max_retries=1)).run(
            AgentRequest("Question")
        )
    )

    assert result.succeeded
    assert result.state.final_answer == "recovered"
    assert result.state.retry_count == 1
    assert result.state.tool_call_count == 2
    assert result.state.sql_attempt_count == 2


def test_tool_call_budget_stops_before_calling_tool():
    tool = MockQueryTool()
    result = asyncio.run(
        make_controller(tool=tool, budget=ExecutionBudget(max_tool_calls=0)).run(
            AgentRequest("Question")
        )
    )

    assert result.state.status == RunStatus.BUDGET_EXHAUSTED
    assert tool.calls == 0


def test_sql_attempt_budget_stops_before_security_validation_or_tool_call():
    class CountingGate:
        calls = 0

        def check(self, sql):
            self.calls += 1
            return type("Decision", (), {"allowed": True, "reason": "allowed"})()

    tool = MockQueryTool()
    gate = CountingGate()
    events = InMemoryEventSink()
    result = asyncio.run(
        make_controller(
            tool=tool,
            gate=gate,
            events=events,
            budget=ExecutionBudget(max_sql_attempts=0),
        ).run(AgentRequest("Question"))
    )

    assert result.state.status == RunStatus.BUDGET_EXHAUSTED
    assert result.state.failure_reason == "sql_attempt_budget_exhausted"
    assert result.state.sql_attempt_count == 0
    assert gate.calls == 0
    assert tool.calls == 0
    assert_single_terminal_event(
        events.events, "budget_exhausted", "budget_exhausted", "sql_attempt_budget_exhausted"
    )


def test_llm_call_budget_stops_before_planning():
    class CountingPlanner:
        calls = 0

        async def create_plan(self, question, context):
            self.calls += 1
            return None

    planner = CountingPlanner()
    result = asyncio.run(
        make_controller(planner=planner, budget=ExecutionBudget(max_llm_calls=0)).run(
            AgentRequest("Question")
        )
    )

    assert result.state.status == RunStatus.BUDGET_EXHAUSTED
    assert planner.calls == 0


def test_query_timeout_is_bounded_and_not_retried_without_budget():
    tool = MockQueryTool(delay_seconds=0.05)
    result = asyncio.run(
        make_controller(
            tool=tool,
            budget=ExecutionBudget(max_retries=0, query_timeout_seconds=0.001),
        ).run(AgentRequest("Question"))
    )

    assert result.state.status == RunStatus.FAILED
    assert result.state.failure_reason == "tool_timeout"
    assert result.state.retry_count == 0


def test_overall_timeout_terminates_a_hung_planner():
    class HungPlanner:
        async def create_plan(self, question, context):
            await asyncio.Event().wait()

    events = InMemoryEventSink()
    result = asyncio.run(
        make_controller(
            planner=HungPlanner(),
            events=events,
            budget=ExecutionBudget(run_timeout_seconds=0.01),
        ).run(AgentRequest("Question"))
    )

    assert result.state.status == RunStatus.TIMED_OUT
    assert result.state.failure_reason == "run_timeout"
    assert result.state.current_step == "timed_out"
    assert_single_terminal_event(events.events, "run_timed_out", "timed_out", "run_timeout")


def test_security_rejection_does_not_call_tool():
    class UnsafePlanner:
        async def create_plan(self, question, context):
            return type("Plan", (), {"sql": "DELETE FROM users", "summary": "unsafe"})()

    tool = MockQueryTool()
    events = InMemoryEventSink()
    result = asyncio.run(
        make_controller(tool=tool, planner=UnsafePlanner(), events=events).run(
            AgentRequest("Question")
        )
    )

    assert result.state.status == RunStatus.REFUSED
    assert result.state.failure_reason == "security_rejection"
    assert tool.calls == 0
    assert_single_terminal_event(events.events, "run_refused", "refused", "security_rejection")


def test_security_gate_exception_fails_closed():
    class RaisingGate:
        def check(self, sql):
            raise RuntimeError("sensitive gate failure details")

    tool = MockQueryTool()
    events = InMemoryEventSink()
    result = asyncio.run(
        make_controller(tool=tool, gate=RaisingGate(), events=events).run(AgentRequest("Question"))
    )

    assert result.state.status == RunStatus.FAILED
    assert result.state.failure_reason == "security_gate_error"
    assert tool.calls == 0
    assert events.events[-1].event_type == "run_failed"
    assert_single_terminal_event(events.events, "run_failed", "failed", "security_gate_error")


def test_retry_revalidates_sql_and_stops_if_gate_rejects():
    class ChangingGate:
        calls = 0

        def check(self, sql):
            self.calls += 1
            allowed = self.calls == 1
            return type("Decision", (), {"allowed": allowed, "reason": "decision"})()

    tool = MockQueryTool(failure=ToolError("temporary"))
    gate = ChangingGate()
    result = asyncio.run(
        make_controller(
            tool=tool,
            gate=gate,
            budget=ExecutionBudget(max_retries=2),
        ).run(AgentRequest("Question"))
    )

    assert result.state.status == RunStatus.REFUSED
    assert result.state.failure_reason == "security_rejection"
    assert gate.calls == 2
    assert tool.calls == 1


def test_memory_and_structured_events_cover_run_lifecycle():
    events = InMemoryEventSink()
    result = asyncio.run(make_controller(events=events).run(AgentRequest("Question")))

    event_types = [event.event_type for event in events.events]
    assert event_types[0] == "run_started"
    assert "plan_created" in event_types
    assert "security_check_completed" in event_types
    assert "tool_call_completed" in event_types
    assert event_types[-1] == "run_completed"
    assert all(event.run_id == result.state.run_id for event in events.events)
    assert all(not hasattr(event, "sql") for event in events.events)
    assert events.events[-1].duration_ms is not None
    assert (
        next(
            event for event in events.events if event.event_type == "tool_call_completed"
        ).duration_ms
        is not None
    )


def test_non_retryable_tool_error_is_not_retried():
    tool = MockQueryTool(failure=ToolError("permanent", retryable=False))
    result = asyncio.run(
        make_controller(tool=tool, budget=ExecutionBudget(max_retries=3)).run(
            AgentRequest("Question")
        )
    )

    assert result.state.status == RunStatus.FAILED
    assert result.state.failure_reason == "tool_error"
    assert result.state.retry_count == 0
    assert tool.calls == 1


def test_unformattable_tool_output_fails_without_retry():
    class UnformattableResult:
        def __str__(self):
            raise ValueError("private result details")

    tool = MockQueryTool(result=UnformattableResult())
    result = asyncio.run(
        make_controller(tool=tool, budget=ExecutionBudget(max_retries=3)).run(
            AgentRequest("Question")
        )
    )

    assert result.state.status == RunStatus.FAILED
    assert result.state.failure_reason == "invalid_tool_output"
    assert result.state.retry_count == 0
    assert tool.calls == 1


def test_planner_and_tool_exceptions_have_clear_terminal_categories():
    class BrokenPlanner:
        async def create_plan(self, question, context):
            raise RuntimeError("private planner details")

    planner_result = asyncio.run(
        make_controller(planner=BrokenPlanner()).run(AgentRequest("Question"))
    )

    events = InMemoryEventSink()

    class BrokenTool(MockQueryTool):
        async def call(self, arguments, *, timeout_seconds):
            self.calls += 1
            raise RuntimeError("private tool details")

    tool = BrokenTool()
    tool_result = asyncio.run(
        make_controller(tool=tool, events=events, budget=ExecutionBudget(max_retries=3)).run(
            AgentRequest("Question")
        )
    )

    assert planner_result.state.failure_reason == "planner_error"
    assert planner_result.state.status == RunStatus.FAILED
    assert tool_result.state.failure_reason == "tool_exception"
    assert tool_result.state.retry_count == 0
    assert tool.calls == 1
    assert_single_terminal_event(events.events, "run_failed", "failed", "tool_exception")


def test_memory_retrieval_failure_does_not_reach_planner_or_tool():
    class BrokenMemory(InMemoryMemory):
        def get(self, run_id, kind=None):
            raise RuntimeError("private memory details")

    class CountingPlanner:
        calls = 0

        async def create_plan(self, question, context):
            self.calls += 1
            return None

    planner = CountingPlanner()
    tool = MockQueryTool()
    result = asyncio.run(
        make_controller(planner=planner, tool=tool, memory=BrokenMemory()).run(
            AgentRequest("Question")
        )
    )

    assert result.state.failure_reason == "memory_error"
    assert result.state.status == RunStatus.FAILED
    assert planner.calls == 0
    assert tool.calls == 0


def test_repeated_runs_have_independent_state_and_run_ids():
    controller = make_controller()

    first = asyncio.run(controller.run(AgentRequest("First")))
    second = asyncio.run(controller.run(AgentRequest("Second")))

    assert first.state.run_id != second.state.run_id
    assert first.state.tool_call_count == second.state.tool_call_count == 1
    assert first.state.sql_attempt_count == second.state.sql_attempt_count == 1


def test_memory_does_not_retain_request_or_raw_tool_result():
    memory = InMemoryMemory()
    tool = MockQueryTool(result="private result payload")
    result = asyncio.run(
        make_controller(tool=tool, memory=memory).run(
            AgentRequest("Question with private user detail")
        )
    )

    stored_values = memory.get(result.state.run_id)
    assert stored_values == ("succeeded",)
    assert all("private" not in value for value in stored_values)


def test_event_sink_failure_fails_closed_before_tool_execution():
    class FailOnceEvents(InMemoryEventSink):
        failed = False

        def emit(self, event):
            if event.event_type == "context_retrieval_started" and not self.failed:
                self.failed = True
                raise RuntimeError("private sink details")
            super().emit(event)

    tool = MockQueryTool()
    events = FailOnceEvents()
    result = asyncio.run(make_controller(tool=tool, events=events).run(AgentRequest("Question")))

    assert result.state.status == RunStatus.FAILED
    assert result.state.failure_reason == "event_sink_error"
    assert tool.calls == 0
    assert_single_terminal_event(events.events, "run_failed", "failed", "event_sink_error")


def test_mock_tool_exposes_input_and_output_schemas():
    tool = MockQueryTool()

    assert tool.input_schema["required"] == ["sql"]
    assert tool.output_schema == {"type": "string"}
