from __future__ import annotations

import asyncio
import os
from collections.abc import Mapping

from sqlguard.agent.controller import AgentController
from sqlguard.agent.models import AgentRequest, ExecutionBudget
from sqlguard.agent.planning import create_planner
from sqlguard.mcp.tools import InProcessToolRegistry, MockQueryTool
from sqlguard.memory.store import InMemoryMemory
from sqlguard.observability.events import InMemoryEventSink
from sqlguard.security.gate import ReadOnlySQLGate


def budget_from_env(env: Mapping[str, str] | None = None) -> ExecutionBudget:
    """Build the demo budget; SQLGUARD_RUN_TIMEOUT_SECONDS overrides the 60s run limit."""
    env = os.environ if env is None else env
    raw = env.get("SQLGUARD_RUN_TIMEOUT_SECONDS")
    if not raw:
        return ExecutionBudget()
    try:
        return ExecutionBudget(run_timeout_seconds=float(raw))
    except ValueError:
        raise ValueError("SQLGUARD_RUN_TIMEOUT_SECONDS must be a positive number") from None


async def run_demo() -> str:
    controller = AgentController(
        budget=budget_from_env(),
        planner=create_planner(),
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
