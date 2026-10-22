import asyncio
from types import SimpleNamespace

import pytest

from sqlguard.mcp.client import McpRemoteTool, McpToolRegistry
from sqlguard.mcp.tools import ToolError


class FakeSession:
    def __init__(self, result=None, error=None, delay=0):
        self.result = result
        self.error = error
        self.delay = delay
        self.calls = []

    async def call_tool(self, name, arguments):
        self.calls.append((name, arguments))
        if self.delay:
            await asyncio.sleep(self.delay)
        if self.error:
            raise self.error
        return self.result


def text(value):
    return SimpleNamespace(type="text", text=value)


def registry(session):
    return McpToolRegistry.from_session(session, {"query": {"type": "object"}})


def call(reg, name="query", timeout=1.0):
    return asyncio.run(reg.call(name, {"sql": "SELECT 1"}, timeout_seconds=timeout))


def test_text_content_is_returned():
    session = FakeSession(SimpleNamespace(isError=False, content=[text("a"), text("b")]))
    assert call(registry(session)) == "a\nb"
    assert session.calls == [("query", {"sql": "SELECT 1"})]


def test_structured_content_preferred():
    session = FakeSession(
        SimpleNamespace(isError=False, structuredContent={"rows": 1}, content=[text("x")])
    )
    assert call(registry(session)) == {"rows": 1}


def test_unknown_tool_not_forwarded():
    session = FakeSession()
    with pytest.raises(ToolError) as info:
        call(registry(session), name="drop")
    assert info.value.category == "unknown_tool"
    assert session.calls == []


def test_remote_error_maps_without_leaking_message():
    session = FakeSession(SimpleNamespace(isError=True, content=[text("secret detail")]))
    with pytest.raises(ToolError) as info:
        call(registry(session))
    assert info.value.category == "mcp_tool_error"
    assert not info.value.retryable
    assert "secret" not in str(info.value)


def test_transport_failure_maps_to_tool_error():
    with pytest.raises(ToolError) as info:
        call(registry(FakeSession(error=RuntimeError("host=10.0.0.1"))))
    assert info.value.category == "mcp_transport_error"
    assert "10.0.0.1" not in str(info.value)


def test_empty_result_is_invalid():
    with pytest.raises(ToolError) as info:
        call(registry(FakeSession(SimpleNamespace(isError=False, content=[]))))
    assert info.value.category == "mcp_invalid_result"


def test_timeout_propagates():
    session = FakeSession(SimpleNamespace(isError=False, content=[text("x")]), delay=1)
    with pytest.raises(TimeoutError):
        call(registry(session), timeout=0.01)


def test_remote_tool_exposes_tool_contract():
    tool = McpRemoteTool(FakeSession(), "query", {"type": "object"})
    assert tool.name == "query"
    assert tool.input_schema == {"type": "object"}
    assert tool.output_schema == {}
