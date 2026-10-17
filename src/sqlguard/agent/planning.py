from __future__ import annotations

from dataclasses import dataclass
from typing import Protocol


@dataclass(frozen=True)
class Plan:
    sql: str
    summary: str


class Planner(Protocol):
    async def create_plan(self, question: str, context: tuple[str, ...]) -> Plan: ...


class DemoPlanner:
    """Deterministic placeholder; it does not interpret questions or call an LLM."""

    async def create_plan(self, question: str, context: tuple[str, ...]) -> Plan:
        del question, context
        return Plan(sql="SELECT 1 AS demo_value", summary="Return a deterministic demo value")
