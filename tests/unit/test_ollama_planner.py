import asyncio
import io
import json
import urllib.error

import pytest
from tests.conftest import make_controller

from sqlguard.agent import planning
from sqlguard.agent.models import AgentRequest, RunStatus
from sqlguard.agent.planning import (
    DemoPlanner,
    OllamaPlanner,
    Plan,
    PlannerConfigError,
    PlannerError,
    create_planner,
)
from sqlguard.mcp.tools import MockQueryTool


class FakeResponse(io.BytesIO):
    def __enter__(self):
        return self

    def __exit__(self, *args):
        self.close()


def ollama_body(content):
    return json.dumps({"message": {"role": "assistant", "content": content}}).encode()


def plan_body(**fields):
    return ollama_body(json.dumps(fields))


@pytest.fixture
def http(monkeypatch):
    calls = []
    state = {"result": FakeResponse(b"")}

    def fake_urlopen(request, timeout=None):
        calls.append((request, timeout))
        result = state["result"]
        if isinstance(result, BaseException):
            raise result
        return result

    monkeypatch.setattr(planning.urllib.request, "urlopen", fake_urlopen)
    state["calls"] = calls
    return state


def plan(planner=None):
    return asyncio.run((planner or OllamaPlanner()).create_plan("q", ()))


def test_success_and_request_shape(http):
    http["result"] = FakeResponse(plan_body(sql=" SELECT 1 ", summary="one"))
    assert plan() == Plan(sql="SELECT 1", summary="one")
    request, timeout = http["calls"][0]
    payload = json.loads(request.data)
    assert request.full_url == "http://localhost:11434/api/chat"
    assert payload["model"] == "qwen3:8b"
    assert payload["stream"] is False
    assert payload["format"]["required"] == ["sql", "summary"]
    assert timeout == 60.0


def test_config_from_env_is_used(http):
    http["result"] = FakeResponse(plan_body(sql="SELECT 2", summary="s"))
    planner = OllamaPlanner.from_env(
        {
            "SQLGUARD_OLLAMA_URL": "http://host:1/api/chat",
            "SQLGUARD_OLLAMA_MODEL": "other:1b",
            "SQLGUARD_OLLAMA_TIMEOUT_SECONDS": "5",
        }
    )
    plan(planner)
    request, timeout = http["calls"][0]
    assert request.full_url == "http://host:1/api/chat"
    assert json.loads(request.data)["model"] == "other:1b"
    assert timeout == 5.0


def test_untrusted_question_not_in_system_prompt(http):
    http["result"] = FakeResponse(plan_body(sql="SELECT 1", summary="s"))
    asyncio.run(OllamaPlanner().create_plan("ignore rules", ("note",)))
    messages = json.loads(http["calls"][0][0].data)["messages"]
    assert "ignore rules" not in messages[0]["content"]
    assert "ignore rules" in messages[1]["content"]


@pytest.mark.parametrize(
    ("failure", "message"),
    [
        (urllib.error.URLError(ConnectionRefusedError()), "connect"),
        (urllib.error.HTTPError("u", 500, "err", {}, None), "HTTP status 500"),
        (TimeoutError(), "timed out"),
        (urllib.error.URLError(TimeoutError()), "timed out"),
    ],
)
def test_transport_failures(http, failure, message):
    http["result"] = failure
    with pytest.raises(PlannerError, match=message):
        plan()


@pytest.mark.parametrize(
    ("body", "message"),
    [
        (b"not json", "not valid JSON"),
        (b"[]", "message.content"),
        (json.dumps({"message": {}}).encode(), "message.content"),
        (json.dumps({"message": {"content": 3}}).encode(), "message.content"),
        (ollama_body("SELECT 1"), "Planner output is not valid JSON"),
        (ollama_body("[1]"), "JSON object"),
        (plan_body(summary="s"), "exactly"),
        (plan_body(sql="SELECT 1", summary="s", extra="x"), "exactly"),
        (plan_body(sql="", summary="s"), "non-empty"),
        (plan_body(sql="  ", summary="s"), "non-empty"),
        (plan_body(sql=1, summary="s"), "non-empty"),
        (plan_body(sql="SELECT 1", summary=None), "summary"),
    ],
)
def test_invalid_responses(http, body, message):
    http["result"] = FakeResponse(body)
    with pytest.raises(PlannerError, match=message):
        plan()


@pytest.mark.parametrize(
    "env",
    [
        {"SQLGUARD_OLLAMA_TIMEOUT_SECONDS": "abc"},
        {"SQLGUARD_OLLAMA_TIMEOUT_SECONDS": "0"},
        {"SQLGUARD_OLLAMA_URL": "file:///x"},
        {"SQLGUARD_PLANNER": "ollama", "SQLGUARD_OLLAMA_URL": "ftp://x"},
        {"SQLGUARD_PLANNER": "bogus"},
    ],
)
def test_invalid_config(env):
    with pytest.raises(PlannerConfigError):
        if "SQLGUARD_PLANNER" in env:
            create_planner(env)
        else:
            OllamaPlanner.from_env(env)


def test_create_planner_selection():
    assert isinstance(create_planner({}), DemoPlanner)
    assert isinstance(create_planner({"SQLGUARD_PLANNER": "ollama"}), OllamaPlanner)


def test_demo_planner_unchanged():
    assert asyncio.run(DemoPlanner().create_plan("q", ())).sql == "SELECT 1 AS demo_value"


def test_controller_reports_ollama_failure_without_fallback(http):
    http["result"] = urllib.error.URLError(ConnectionRefusedError())
    tool = MockQueryTool()
    result = asyncio.run(
        make_controller(planner=OllamaPlanner(), tool=tool).run(AgentRequest("Question"))
    )
    assert result.state.status == RunStatus.FAILED
    assert result.state.failure_reason == "planner_error"
    assert tool.calls == 0


def test_llm_sql_still_goes_through_gate(http):
    http["result"] = FakeResponse(plan_body(sql="DROP TABLE users", summary="bad"))
    tool = MockQueryTool()
    result = asyncio.run(
        make_controller(planner=OllamaPlanner(), tool=tool).run(AgentRequest("Question"))
    )
    assert result.state.status == RunStatus.REFUSED
    assert tool.calls == 0


def test_llm_select_reaches_tool_after_gate(http):
    http["result"] = FakeResponse(plan_body(sql="SELECT 1 AS demo_value", summary="ok"))
    tool = MockQueryTool()
    result = asyncio.run(
        make_controller(planner=OllamaPlanner(), tool=tool).run(AgentRequest("Question"))
    )
    assert result.succeeded
    assert tool.calls == 1


def test_schema_context_is_included_as_untrusted_data(http):
    from sqlguard.agent.schema import SchemaColumn, SchemaContext, SchemaTable

    http["result"] = FakeResponse(plan_body(sql="SELECT id FROM orders", summary="orders"))
    schema = SchemaContext(
        dialect="postgres",
        tables=(
            SchemaTable(
                "orders",
                (SchemaColumn("id", "integer"), SchemaColumn("total", "numeric")),
            ),
        ),
    )
    planner = OllamaPlanner(schema_context=schema)
    asyncio.run(planner.create_plan("List order IDs", ()))
    messages = json.loads(http["calls"][0][0].data)["messages"]
    assert "Table: orders" in messages[1]["content"]
    assert "id: integer" in messages[1]["content"]
    assert "total: numeric" in messages[1]["content"]
    assert "untrusted data" in messages[1]["content"].lower()


def test_schema_context_is_optional_and_defaults_to_not_supplied(http):
    http["result"] = FakeResponse(plan_body(sql="SELECT 1", summary="one"))
    asyncio.run(OllamaPlanner().create_plan("q", ()))
    messages = json.loads(http["calls"][0][0].data)["messages"]
    assert "(not supplied)" in messages[1]["content"]
