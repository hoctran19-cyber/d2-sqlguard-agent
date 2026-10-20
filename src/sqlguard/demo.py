from __future__ import annotations

import asyncio
import os
import sys
from collections.abc import Mapping
from dataclasses import dataclass, field
from typing import Any

from sqlguard.agent.controller import AgentController
from sqlguard.agent.models import AgentRequest, ExecutionBudget
from sqlguard.agent.planning import OllamaPlanner, Planner, PlannerConfigError, create_planner
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
    gate_checks: list[GateCheck] = field(default_factory=list)
    tool_sql: list[str] = field(default_factory=list)


class _RecordingGate:
    """Delegates to the real gate and records the exact SQL it was asked to check."""

    def __init__(self, gate: SecurityGate, checks: list[GateCheck]) -> None:
        self._gate = gate
        self._checks = checks

    def check(self, sql: str) -> SecurityDecision:
        decision = self._gate.check(sql)
        self._checks.append(GateCheck(sql=sql, allowed=decision.allowed, reason=decision.reason))
        return decision


class _RecordingTools(InProcessToolRegistry):
    """Records the exact SQL that reaches the tool."""

    def __init__(self, tools: list[Tool], calls: list[str]) -> None:
        super().__init__(tools)
        self._calls = calls

    async def call(self, name: str, arguments: dict[str, Any], *, timeout_seconds: float) -> Any:
        sql = arguments.get("sql")
        if isinstance(sql, str):
            self._calls.append(sql)
        return await super().call(name, arguments, timeout_seconds=timeout_seconds)


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


def _planner_label(planner: Planner) -> tuple[str, str | None]:
    if isinstance(planner, OllamaPlanner):
        return "ollama", planner.model
    return "demo", None


async def run_demo_report(
    planner: Planner | None = None,
    *,
    gate: SecurityGate | None = None,
    tool: MockQueryTool | None = None,
    budget: ExecutionBudget | None = None,
) -> DemoReport:
    planner = planner or create_planner()
    name, model = _planner_label(planner)
    checks: list[GateCheck] = []
    tool_sql: list[str] = []
    controller = AgentController(
        planner=planner,
        tools=_RecordingTools([tool or MockQueryTool()], tool_sql),
        security_gate=_RecordingGate(gate or ReadOnlySQLGate(), checks),
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
        gate_checks=checks,
        tool_sql=tool_sql,
    )


def format_report(report: DemoReport) -> str:
    lines = [f"planner: {report.planner}"]
    if report.model:
        lines.append(f"model: {report.model}")
    lines.append("tool: MockQueryTool (mock; no database is queried)")
    if not report.gate_checks:
        lines.append("proposed_sql: (none; the planner produced no SQL for the gate)")
    for number, check in enumerate(report.gate_checks, start=1):
        lines.append(f"proposed_sql[{number}]: {check.sql}")
        verdict = "allowed" if check.allowed else "rejected"
        lines.append(f"security_gate[{number}]: {verdict} ({check.reason})")
    for number, sql in enumerate(report.tool_sql, start=1):
        lines.append(f"mock_tool_sql[{number}]: {sql}")
    if report.succeeded:
        lines.append(f"mock_result: {report.final_answer}")
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
    print(format_report(report))
    return 0 if report.succeeded else 1


if __name__ == "__main__":
    sys.exit(main())
