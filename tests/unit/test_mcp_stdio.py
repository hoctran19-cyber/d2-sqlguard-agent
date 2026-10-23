import asyncio
import os
import shutil
import sqlite3
import subprocess
from pathlib import Path

import pytest

pytest.importorskip("mcp")

from sqlguard.mcp.client import McpStdioConnection, sqlite_server_connection  # noqa: E402
from sqlguard.mcp.tools import ToolError  # noqa: E402

SRC = str(Path(__file__).resolve().parents[2] / "src")
# Tiến trình con chạy module trực tiếp từ workspace, không phụ thuộc vào gói đã cài editable.
ENV = {"PYTHONPATH": SRC}
ALLOWED_SQL = "SELECT order_id, total_amount_vnd FROM orders ORDER BY order_id LIMIT 2"


@pytest.fixture
def db(tmp_path):
    path = tmp_path / "mcp.db"
    with sqlite3.connect(path) as connection:
        connection.executescript(
            """
            CREATE TABLE orders (order_id INTEGER, customer_id INTEGER, order_date TEXT,
                status TEXT, channel TEXT, total_amount_vnd INTEGER, note TEXT);
            INSERT INTO orders VALUES (1, 10, '2025-01-01', 'completed', 'web', 1200, 'a'),
                (2, 11, '2025-01-02', 'completed', 'store', 2300, 'b');
            CREATE TABLE customers (customer_id INTEGER, full_name TEXT, phone_number TEXT);
            CREATE TABLE secret_table (secret TEXT);
            """
        )
    return path


def run(coro):
    return asyncio.run(coro)


def connect(db, role="sales"):
    return sqlite_server_connection(db, role, extra_env=ENV)


@pytest.mark.parametrize("key", ["SQLGUARD_MCP_ROLE", "SQLGUARD_SQLITE_PATH"])
def test_reserved_server_environment_cannot_be_overridden(tmp_path, key):
    with pytest.raises(ValueError, match=key):
        sqlite_server_connection(tmp_path / "db.sqlite", "sales", extra_env={key: "override"})


def test_discovers_tools_and_runs_allowed_query(db):
    async def scenario():
        async with connect(db) as connection:
            registry = await connection.registry()
            result = await registry.call("query", {"sql": ALLOWED_SQL}, timeout_seconds=10)
            schema = await registry.call("get_schema", {}, timeout_seconds=10)
            return result, schema

    result, schema = run(scenario())
    assert result["trust"] == "untrusted"
    assert result["rows"] == [[1, 1200], [2, 2300]]
    tables = {t["name"]: {c["name"] for c in t["columns"]} for t in schema["tables"]}
    assert "secret_table" not in tables
    assert "phone_number" not in tables["customers"]


def test_discovery_lists_expected_tools(db):
    async def scenario():
        async with connect(db) as connection:
            listing = await connection.session.list_tools()
            return {tool.name for tool in listing.tools}

    assert run(scenario()) == {"query", "get_schema"}


@pytest.mark.parametrize(
    "sql",
    [
        "DELETE FROM orders",
        "SELECT secret FROM secret_table",
        "SELECT phone_number FROM customers",
        "SELECT 1; DROP TABLE orders",
    ],
)
def test_gate_rejects_unsafe_queries(db, sql):
    async def scenario():
        async with connect(db) as connection:
            registry = await connection.registry()
            await registry.call("query", {"sql": sql}, timeout_seconds=10)

    with pytest.raises(ToolError) as info:
        run(scenario())
    assert info.value.category == "security_rejection"
    assert not info.value.retryable


def test_role_argument_from_model_cannot_change_role(db):
    # Dù truyền thêm role giả, quyền thực tế vẫn thuộc role cấu hình ở lúc khởi chạy server.
    async def scenario():
        async with connect(db) as connection:
            registry = await connection.registry()
            await registry.call(
                "query",
                {"sql": "SELECT phone_number FROM customers", "role": "admin"},
                timeout_seconds=10,
            )

    with pytest.raises(ToolError) as info:
        run(scenario())
    assert info.value.category == "security_rejection"


def test_unknown_tool_is_rejected_locally(db):
    async def scenario():
        async with connect(db) as connection:
            registry = await connection.registry()
            await registry.call("shell", {"cmd": "id"}, timeout_seconds=10)

    with pytest.raises(ToolError) as info:
        run(scenario())
    assert info.value.category == "unknown_tool"


def test_client_timeout(db):
    async def scenario():
        async with connect(db) as connection:
            registry = await connection.registry()
            await registry.call("query", {"sql": ALLOWED_SQL}, timeout_seconds=0.0001)

    with pytest.raises(TimeoutError):
        run(scenario())


def test_server_that_cannot_start_raises(db):
    # Không cấu hình role nên server phải dừng trong lúc khởi động, thay vì mở phiên thiếu quyền.
    bad = McpStdioConnection(
        "python3", ["-m", "sqlguard.mcp.server"], {**ENV, "SQLGUARD_SQLITE_PATH": str(db)}
    )

    async def scenario():
        async with bad:
            pass

    with pytest.raises(Exception):  # noqa: B017 - server thoát trước handshake do thiếu role
        run(asyncio.wait_for(scenario(), timeout=20))


def test_session_closed_after_exit_and_process_gone(db):
    # Sau khi thoát context, registry cũ không được gọi tiếp và subprocess phải kết thúc.
    async def scenario():
        async with connect(db) as connection:
            registry = await connection.registry()
        assert connection.session is None
        with pytest.raises(ToolError) as info:
            await registry.call("query", {"sql": ALLOWED_SQL}, timeout_seconds=5)
        with pytest.raises(ToolError):
            await connection.registry()
        return info.value.category

    assert run(scenario()) == "mcp_transport_error"
    if shutil.which("pgrep"):
        children = subprocess.run(
            ["pgrep", "-f", "-P", str(os.getpid()), "sqlguard.mcp.server"], capture_output=True
        )
        assert children.returncode == 1
