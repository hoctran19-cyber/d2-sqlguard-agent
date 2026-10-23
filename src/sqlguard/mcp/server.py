"""Máy chủ MCP qua STDIO, cung cấp công cụ đọc schema và truy vấn SQLite chỉ đọc.

Khởi chạy bằng ``python -m sqlguard.mcp.server``. Role và đường dẫn cơ sở dữ liệu được
đọc từ môi trường của tiến trình máy chủ (``SQLGUARD_MCP_ROLE`` và
``SQLGUARD_SQLITE_PATH``); công cụ truy vấn chỉ nhận chuỗi SQL, không nhận role hay
quyền từ LLM. Mọi câu lệnh đều đi qua runtime bảo mật dùng chung, bao gồm Security Gate,
``SQLiteExecutor``, giới hạn số dòng/kích thước kết quả, bộ lọc dữ liệu, kiểm tra canary
và ghi audit. Nếu cấu hình không hợp lệ, máy chủ dừng thay vì chuyển sang chế độ kém an toàn.
"""

from __future__ import annotations

import asyncio
import json
import os
import sys
from collections.abc import Mapping
from typing import Any
from uuid import uuid4

from mcp.server.mcpserver import MCPServer
from mcp_types import CallToolResult, TextContent

from sqlguard.agent.postgres_schema import SchemaAdapterError
from sqlguard.agent.runtime import (
    QUERY_SOURCE_ENV,
    QueryRuntimeError,
    QueryRuntimeFactory,
    build_query_runtime_factory,
)
from sqlguard.agent.sqlite_schema import SQLiteSchemaAdapter
from sqlguard.mcp.tools import ToolError
from sqlguard.security.service import SecurityToolError

ROLE_ENV = "SQLGUARD_MCP_ROLE"


def _error(category: str, retryable: bool, detail: str | None = None) -> CallToolResult:
    # Chỉ trả mã lỗi đã chuẩn hóa và thông tin an toàn từ gate; không để lộ lỗi SQLite,
    # câu lệnh nội bộ hay chi tiết transport ra phía client MCP.
    return CallToolResult(
        content=[TextContent(type="text", text=detail or category)],
        structured_content={"category": category, "retryable": retryable},
        is_error=True,
    )


def build_server(env: Mapping[str, str] | None = None) -> MCPServer:
    env = dict(os.environ if env is None else env)
    # Server này chỉ phục vụ SQLite; ép nguồn truy vấn tại đây để không thể bị cấu hình
    # sang PostgreSQL hoặc chế độ mock ngoài ý muốn.
    env[QUERY_SOURCE_ENV] = "sqlite"
    factory = build_query_runtime_factory(env.get(ROLE_ENV), env)
    if factory is None:  # pragma: no cover - nguồn đã được cố định là SQLite ở phía trên
        raise QueryRuntimeError("query_invalid_config")
    return _create_server(factory, env)


def _create_server(factory: QueryRuntimeFactory, env: Mapping[str, str]) -> MCPServer:
    server = MCPServer("sqlguard-sqlite")
    schema_adapter = SQLiteSchemaAdapter.from_env(factory.policy, env=env)
    # Dùng cùng giới hạn thời gian trong policy cho cả truy vấn và đọc schema.
    timeout = factory.policy.limits.query_timeout_seconds

    @server.tool(name="query", description="Run one read-only SELECT against the SQLite database.")
    async def query(sql: str) -> CallToolResult:
        # Mỗi yêu cầu có runtime riêng để không dùng chung context, bộ đếm gate hay
        # trạng thái tool giữa các lần gọi; role vẫn lấy từ cấu hình đáng tin cậy.
        runtime = factory.for_run(str(uuid4()))
        try:
            envelope = await asyncio.wait_for(
                runtime.tool.call({"sql": sql}, timeout_seconds=timeout), timeout=timeout
            )
        except SecurityToolError as error:
            return _error("security_rejection", False, error.decision.reason)
        except ToolError as error:
            return _error(error.category, error.retryable)
        except TimeoutError:
            return _error("db_timeout", True)
        except Exception:
            return _error("tool_exception", False)
        return CallToolResult(
            content=[TextContent(type="text", text=json.dumps(envelope, ensure_ascii=False))],
            structured_content=envelope,
        )

    @server.tool(name="get_schema", description="Tables and columns the configured role may read.")
    async def get_schema() -> CallToolResult:
        # Adapter chỉ trả các bảng/cột mà policy cho phép role cấu hình được đọc.
        try:
            schema = await asyncio.wait_for(schema_adapter.load(factory.role), timeout=timeout)
        except SchemaAdapterError as error:
            return _error(error.category, error.retryable)
        except TimeoutError:
            return _error("schema_timeout", True)
        except Exception:
            return _error("tool_exception", False)
        payload: dict[str, Any] = {
            "dialect": schema.dialect,
            "tables": [
                {
                    "name": table.name,
                    "columns": [{"name": c.name, "type": c.data_type} for c in table.columns],
                }
                for table in schema.tables
            ],
        }
        return CallToolResult(
            content=[TextContent(type="text", text=json.dumps(payload))],
            structured_content=payload,
        )

    return server


def main() -> None:
    try:
        server = build_server()
    except (QueryRuntimeError, SchemaAdapterError) as error:
        # Ghi nhóm lỗi ra stderr để chẩn đoán khởi động, không in thông tin cấu hình nhạy cảm.
        print(f"sqlguard MCP server not started: {error.category}", file=sys.stderr)
        raise SystemExit(2) from None
    server.run("stdio")


if __name__ == "__main__":
    main()
