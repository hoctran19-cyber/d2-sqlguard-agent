import asyncio

from tests.conftest import make_controller

from sqlguard.agent.models import AgentRequest, ExecutionBudget, RunStatus
from sqlguard.mcp.tools import MockQueryTool, ToolError
from sqlguard.memory.store import InMemoryMemory
from sqlguard.observability.events import InMemoryEventSink


def test_valid_request_completes_demo_flow():
    result = asyncio.run(make_controller().run(AgentRequest("Show the demo")))

    assert result.succeeded
    assert result.state.status == RunStatus.SUCCEEDED
    assert result.state.final_answer == "demo_value=1"
    assert result.state.llm_call_count == 1
    assert result.state.tool_call_count == 1


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


def test_tool_call_budget_stops_before_calling_tool():
    tool = MockQueryTool()
    result = asyncio.run(
        make_controller(tool=tool, budget=ExecutionBudget(max_tool_calls=0)).run(
            AgentRequest("Question")
        )
    )

    assert result.state.status == RunStatus.BUDGET_EXHAUSTED
    assert tool.calls == 0


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


def test_security_rejection_does_not_call_tool():
    class UnsafePlanner:
        async def create_plan(self, question, context):
            return type("Plan", (), {"sql": "DELETE FROM users", "summary": "unsafe"})()

    tool = MockQueryTool()
    result = asyncio.run(
        make_controller(tool=tool, planner=UnsafePlanner()).run(AgentRequest("Question"))
    )

    assert result.state.failure_reason == "security_rejection"
    assert tool.calls == 0


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


def test_mock_tool_exposes_input_and_output_schemas():
    tool = MockQueryTool()

    assert tool.input_schema["required"] == ["sql"]
    assert tool.output_schema == {"type": "string"}
