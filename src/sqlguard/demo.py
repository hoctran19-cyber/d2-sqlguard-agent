from __future__ import annotations

import asyncio

from sqlguard.agent.controller import AgentController
from sqlguard.agent.models import AgentRequest
from sqlguard.agent.planning import DemoPlanner
from sqlguard.mcp.tools import InProcessToolRegistry, MockQueryTool
from sqlguard.memory.store import InMemoryMemory
from sqlguard.observability.events import InMemoryEventSink
from sqlguard.security.gate import ReadOnlySQLGate


async def run_demo() -> str:
    controller = AgentController(
        planner=DemoPlanner(),
        tools=InProcessToolRegistry([MockQueryTool()]),
        security_gate=ReadOnlySQLGate(),
        memory=InMemoryMemory(),
        events=InMemoryEventSink(),
    )
    result = await controller.run(AgentRequest(question="Show the demo value"))
    if not result.succeeded:
        raise RuntimeError(result.state.failure_reason)
    return result.state.final_answer or ""


def main() -> None:
    print(asyncio.run(run_demo()))


if __name__ == "__main__":
    main()
