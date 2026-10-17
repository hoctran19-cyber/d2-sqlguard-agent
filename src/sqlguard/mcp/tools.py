from __future__ import annotations

import asyncio
from dataclasses import dataclass
from typing import Any, Protocol


class ToolError(Exception):
    def __init__(self, message: str, *, category: str = "tool_error", retryable: bool = True):
        super().__init__(message)
        self.category = category
        self.retryable = retryable


class Tool(Protocol):
    name: str
    input_schema: dict[str, Any]
    output_schema: dict[str, Any]

    async def call(self, arguments: dict[str, Any], *, timeout_seconds: float) -> Any: ...


class ToolRegistry(Protocol):
    async def call(
        self, name: str, arguments: dict[str, Any], *, timeout_seconds: float
    ) -> Any: ...


@dataclass
class MockQueryTool:
    """Local demonstration tool; it does not connect to or query a database."""

    name: str = "query"
    result: Any = "demo_value=1"
    failure: ToolError | None = None
    delay_seconds: float = 0
    calls: int = 0

    @property
    def input_schema(self) -> dict[str, Any]:
        return {
            "type": "object",
            "required": ["sql"],
            "properties": {"sql": {"type": "string"}},
        }

    @property
    def output_schema(self) -> dict[str, Any]:
        return {"type": "string"}

    async def call(self, arguments: dict[str, Any], *, timeout_seconds: float) -> Any:
        del timeout_seconds
        self.calls += 1
        if self.delay_seconds:
            await asyncio.sleep(self.delay_seconds)
        if self.failure is not None:
            raise self.failure
        if not isinstance(arguments.get("sql"), str):
            raise ToolError(
                "SQL argument is required", category="invalid_tool_input", retryable=False
            )
        return self.result


class InProcessToolRegistry:
    def __init__(self, tools: list[Tool]) -> None:
        self._tools = {tool.name: tool for tool in tools}

    async def call(self, name: str, arguments: dict[str, Any], *, timeout_seconds: float) -> Any:
        tool = self._tools.get(name)
        if tool is None:
            raise ToolError("Unknown tool", category="unknown_tool", retryable=False)
        return await tool.call(arguments, timeout_seconds=timeout_seconds)
