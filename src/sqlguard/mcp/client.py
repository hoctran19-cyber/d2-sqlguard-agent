from __future__ import annotations

import asyncio
import re
import sys
from collections.abc import Iterable, Mapping
from contextlib import AsyncExitStack
from pathlib import Path
from typing import Any, Protocol

from sqlguard.mcp.tools import Tool, ToolError


class McpSession(Protocol):
    """Tập phương thức MCP session mà registry cần để liệt kê và gọi công cụ."""

    async def call_tool(self, name: str, arguments: dict[str, Any]) -> Any: ...

    async def list_tools(self) -> Any: ...


class McpRemoteTool:
    """Bọc một công cụ MCP từ xa theo contract ``Tool`` nội bộ."""

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
            # Chuẩn hóa lỗi kết nối, không chuyển chi tiết transport có thể chứa thông tin nhạy cảm
            # lên controller.
            raise ToolError("MCP call failed", category="mcp_transport_error") from None
        return _unwrap(result)


_CATEGORY = re.compile(r"[a-z][a-z0-9_]{0,63}")


def _field(obj: Any, snake: str, camel: str) -> Any:
    # SDK MCP 2.x dùng snake_case; nhánh camelCase hỗ trợ session giả và adapter tương thích.
    value = getattr(obj, snake, None)
    return value if value is not None else getattr(obj, camel, None)


def _unwrap(result: Any) -> Any:
    structured = _field(result, "structured_content", "structuredContent")
    if _field(result, "is_error", "isError"):
        category, retryable = "mcp_tool_error", False
        if isinstance(structured, dict):
            remote = structured.get("category")
            # Chỉ chấp nhận mã lỗi dạng định danh; không để server từ xa đưa chuỗi tùy ý
            # vào category rồi ảnh hưởng đến luồng xử lý lỗi của ứng dụng.
            if isinstance(remote, str) and _CATEGORY.fullmatch(remote):
                category = remote
                retryable = structured.get("retryable") is True
        raise ToolError("MCP tool reported an error", category=category, retryable=retryable)
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
    """Triển khai ``ToolRegistry``, chỉ chuyển tiếp tên công cụ đã được đăng ký."""

    def __init__(self, tools: Iterable[Tool]) -> None:
        self._tools = {tool.name: tool for tool in tools}

    @classmethod
    def from_session(
        cls, session: McpSession, schemas: dict[str, dict[str, Any]]
    ) -> McpToolRegistry:
        """Tạo registry từ allow-list tường minh dạng ``{tên công cụ: input schema}``."""
        return cls(McpRemoteTool(session, name, schema) for name, schema in schemas.items())

    async def call(self, name: str, arguments: dict[str, Any], *, timeout_seconds: float) -> Any:
        tool = self._tools.get(name)
        if tool is None:
            raise ToolError("Unknown tool", category="unknown_tool", retryable=False)
        return await tool.call(arguments, timeout_seconds=timeout_seconds)

    @classmethod
    async def discover(
        cls, session: McpSession, *, allowed: Iterable[str] | None = None
    ) -> McpToolRegistry:
        """Khám phá ``tools/list`` của server, có thể giới hạn theo tập tên ``allowed``."""
        try:
            listing = await session.list_tools()
        except Exception:
            raise ToolError("MCP discovery failed", category="mcp_transport_error") from None
        permitted = None if allowed is None else set(allowed)
        tools = [
            McpRemoteTool(
                session,
                tool.name,
                _field(tool, "input_schema", "inputSchema") or {},
                _field(tool, "output_schema", "outputSchema"),
            )
            for tool in listing.tools
            if permitted is None or tool.name in permitted
        ]
        return cls(tools)


class McpStdioConnection:
    """Quản lý vòng đời tiến trình server STDIO và session MCP qua ``async with``."""

    def __init__(
        self,
        command: str,
        args: list[str],
        env: Mapping[str, str] | None = None,
        *,
        allowed_tools: Iterable[str] | None = None,
    ) -> None:
        self._command = command
        self._args = args
        self._env = dict(env) if env is not None else None
        self._allowed_tools = None if allowed_tools is None else frozenset(allowed_tools)
        self._stack: AsyncExitStack | None = None
        self.session: McpSession | None = None

    async def __aenter__(self) -> McpStdioConnection:
        # Nhập SDK khi thực sự mở kết nối để các chế độ không dùng MCP không cần tải module này.
        from mcp import ClientSession, StdioServerParameters, stdio_client

        stack = AsyncExitStack()
        try:
            params = StdioServerParameters(command=self._command, args=self._args, env=self._env)
            # ExitStack đảm bảo session và subprocess đều được đóng nếu khởi tạo hoặc handshake lỗi.
            read, write = await stack.enter_async_context(stdio_client(params))
            session = await stack.enter_async_context(ClientSession(read, write))
            await session.initialize()
        except BaseException:
            # Đóng mọi tài nguyên đã mở dở rồi giữ nguyên exception để caller xử lý.
            await stack.aclose()
            raise
        self._stack = stack
        self.session = session
        return self

    async def __aexit__(self, *exc_info: object) -> None:
        # Xóa tham chiếu trước khi await để đối tượng không còn được xem là đang kết nối
        # nếu thao tác đóng tài nguyên phát sinh lỗi.
        stack, self._stack, self.session = self._stack, None, None
        if stack is not None:
            await stack.aclose()

    async def registry(self, *, allowed: Iterable[str] | None = None) -> McpToolRegistry:
        if self.session is None:
            raise ToolError("MCP session is closed", category="mcp_transport_error")
        if self._allowed_tools is None:
            permitted = allowed
        elif allowed is None:
            permitted = self._allowed_tools
        else:
            permitted = self._allowed_tools.intersection(allowed)
        return await McpToolRegistry.discover(self.session, allowed=permitted)


def sqlite_server_connection(
    database: str | Path,
    role: str,
    *,
    extra_env: Mapping[str, str] | None = None,
) -> McpStdioConnection:
    """Tạo kết nối tới ``sqlguard.mcp.server`` cục bộ gắn với role và tệp SQLite đã chỉ định.

    ``role`` phải đến từ cấu hình đáng tin cậy của backend hoặc session đã xác thực,
    tuyệt đối không lấy từ nội dung model tạo. Server chỉ nhận giá trị này qua môi trường
    tiến trình khi khởi chạy.
    """
    reserved = {"SQLGUARD_MCP_ROLE", "SQLGUARD_SQLITE_PATH"}
    conflicts = reserved.intersection(extra_env or {})
    if conflicts:
        names = ", ".join(sorted(conflicts))
        raise ValueError(f"extra_env cannot override reserved variables: {names}")

    env = {
        "SQLGUARD_MCP_ROLE": role,
        "SQLGUARD_SQLITE_PATH": str(database),
        **(extra_env or {}),
    }
    return McpStdioConnection(
        sys.executable,
        ["-m", "sqlguard.mcp.server"],
        env,
        allowed_tools={"query", "get_schema"},
    )
