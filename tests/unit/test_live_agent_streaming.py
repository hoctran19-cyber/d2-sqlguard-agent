import asyncio

from tests.conftest import make_controller

from sqlguard.agent.models import AgentRequest
from sqlguard.agent.planning import Plan
from sqlguard.memory.store import InMemoryMemory
from sqlguard.observability.events import (
    CompositeEventSink,
    InMemoryEventSink,
    LiveEventHub,
    LiveEventSink,
)


def test_agent_events_reach_subscriber_before_run_finishes_and_remain_run_scoped():
    async def exercise():
        run_id = "4e1637f4-0ec9-4321-9cbb-21fc29d3406f"
        planner_started = asyncio.Event()
        release_planner = asyncio.Event()

        class WaitingPlanner:
            async def create_plan(self, question, context):
                assert question == "show demo"
                assert context == ()
                planner_started.set()
                await release_planner.wait()
                return Plan("SELECT 1 AS value", "Return one demo value")

        hub = LiveEventHub()
        hub.prepare(run_id)
        subscription = hub.subscribe(run_id)
        memory_events = InMemoryEventSink()
        controller = make_controller(
            planner=WaitingPlanner(),
            events=CompositeEventSink((memory_events, LiveEventSink(hub))),
            memory=InMemoryMemory(),
        )

        task = asyncio.create_task(controller.run(AgentRequest("show demo", run_id=run_id)))
        received = []
        while True:
            sequence, event = await asyncio.wait_for(subscription.queue.get(), timeout=1)
            received.append((sequence, event))
            if event.event_type == "llm_call_started":
                break

        assert planner_started.is_set()
        assert not task.done()
        assert [event.event_type for _, event in received] == [
            "run_started",
            "schema_context_ready",
            "context_retrieval_started",
            "context_retrieval_completed",
            "llm_call_started",
        ]
        assert all(event.run_id == run_id for _, event in received)
        assert received[0][1].data["question"] == "show demo"

        release_planner.set()
        result = await task
        while True:
            item = await asyncio.wait_for(subscription.queue.get(), timeout=1)
            if item is None:
                break
            received.append(item)

        assert result.succeeded
        assert [sequence for sequence, _ in received] == list(range(1, len(received) + 1))
        sql_event = next(event for _, event in received if event.event_type == "plan_created")
        assert sql_event.data["sql"] == "SELECT 1 AS value"
        assert sql_event.module == "planner"
        assert sql_event.attempt_id == "sql-1"
        assert received[-1][1].event_type == "run_completed"
        assert received[-1][1].run_id == run_id

        hub.unsubscribe(run_id, subscription.subscriber_id)

    asyncio.run(exercise())
