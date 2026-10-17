from sqlguard.agent.controller import AgentController
from sqlguard.agent.models import ExecutionBudget
from sqlguard.agent.planning import DemoPlanner
from sqlguard.mcp.tools import InProcessToolRegistry, MockQueryTool
from sqlguard.memory.store import InMemoryMemory
from sqlguard.observability.events import InMemoryEventSink
from sqlguard.security.gate import ReadOnlySQLGate


def make_controller(
    *, tool=None, planner=None, gate=None, memory=None, events=None, budget=None
) -> AgentController:
    return AgentController(
        planner=planner or DemoPlanner(),
        tools=InProcessToolRegistry([tool or MockQueryTool()]),
        security_gate=gate or ReadOnlySQLGate(),
        memory=memory or InMemoryMemory(),
        events=events or InMemoryEventSink(),
        budget=budget or ExecutionBudget(),
    )
