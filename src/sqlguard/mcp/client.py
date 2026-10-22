from __future__ import annotations

import asyncio
from collections.abc import Iterable
from typing import Any, Protocol

from sqlguard.mcp.tools import Tool, ToolError


class McpSession(Protocol):
    """Subset of an MCP client session (e.g. ``mcp.ClientSession``) used by the registry."""

    async def call_tool(self, name: str, arguments: dict[str, Any]) -> Any: ...


class McpRemoteTool:
    """Adapts one remote MCP tool to the local ``Tool`` contract."""

    def __init__(
        self,
        session: McpSession,
        name: str,
        input_schema: dict[str, Any],
        output_schema: dict[str, Any] | None = None,
    ) -> None:
        self._session = session
        self.name = name
        self.input_schema = input_schema
        self.output_schema = output_schema or {}

    async def call(self, arguments: dict[str, Any], *, timeout_seconds: float) -> Any:
        try:
            result = await asyncio.wait_for(
                self._session.call_tool(self.name, arguments), timeout=timeout_seconds
            )
        except TimeoutError:
            raise
        except ToolError:
            raise
        except Exception:
            # Transport details are not propagated to the controller.
            raise ToolError("MCP call failed", category="mcp_transport_error") from None
        return _unwrap(result)


def _unwrap(result: Any) -> Any:
    if getattr(result, "isError", False):
        raise ToolError("MCP tool reported an error", category="mcp_tool_error", retryable=False)
    structured = getattr(result, "structuredContent", None)
    if structured is not None:
        return structured
    texts = [
        item.text
        for item in getattr(result, "content", None) or []
        if getattr(item, "type", None) == "text" and isinstance(getattr(item, "text", None), str)
    ]
    if not texts:
        raise ToolError(
            "MCP result has no usable content", category="mcp_invalid_result", retryable=False
        )
    return "\n".join(texts)


class McpToolRegistry:
    """``ToolRegistry`` that forwards only allow-listed tool names to an MCP session."""

    def __init__(self, tools: Iterable[Tool]) -> None:
        self._tools = {tool.name: tool for tool in tools}

    @classmethod
    def from_session(
        cls, session: McpSession, schemas: dict[str, dict[str, Any]]
    ) -> McpToolRegistry:
        """Build from an explicit ``{tool name: input schema}`` allow-list."""
        return cls(McpRemoteTool(session, name, schema) for name, schema in schemas.items())

    async def call(self, name: str, arguments: dict[str, Any], *, timeout_seconds: float) -> Any:
        tool = self._tools.get(name)
        if tool is None:
            raise ToolError("Unknown tool", category="unknown_tool", retryable=False)
        return await tool.call(arguments, timeout_seconds=timeout_seconds)
