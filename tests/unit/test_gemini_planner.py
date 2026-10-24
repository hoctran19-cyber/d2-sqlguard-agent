import asyncio
import io
import json
import re
import urllib.error

import pytest
from tests.conftest import make_controller

from sqlguard.agent import planning
from sqlguard.agent.models import AgentRequest, RunStatus
from sqlguard.agent.planning import (
    GeminiPlanner,
    OllamaPlanner,
    Plan,
    PlannerBlockedError,
    PlannerConfigError,
    PlannerError,
    RepairFeedback,
    create_planner,
)
from sqlguard.agent.runtime import create_planner_for_role
from sqlguard.agent.schema import SchemaColumn, SchemaContext, SchemaTable
from sqlguard.mcp.tools import MockQueryTool
from sqlguard.security.policy import load_default_policy

KEY = "test-key-not-real"


class FakeResponse(io.BytesIO):
    def __enter__(self):
        return self

    def __exit__(self, *args):
        self.close()


def gemini_body(text, *, finish="STOP", extra_parts=()):
    parts = [*extra_parts, {"text": text}]
    return json.dumps(
        {"candidates": [{"content": {"role": "model", "parts": parts}, "finishReason": finish}]}
    ).encode()


def plan_body(**fields):
    return gemini_body(json.dumps(fields))


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


def gemini(**kwargs):
    return GeminiPlanner(api_key=KEY, **kwargs)


def plan(planner=None):
    return asyncio.run((planner or gemini()).create_plan("q", ()))


def test_success_and_request_shape(http):
    http["result"] = FakeResponse(plan_body(sql=" SELECT 1 ", summary="one"))
    assert plan() == Plan(sql="SELECT 1", summary="one")
    request, timeout = http["calls"][0]
    payload = json.loads(request.data)
    assert request.full_url == (
        "https://generativelanguage.googleapis.com/v1beta/models/gemini-2.5-flash:generateContent"
    )
    assert payload["generationConfig"]["temperature"] == 0
    assert payload["generationConfig"]["responseMimeType"] == "application/json"
    assert payload["generationConfig"]["responseSchema"]["required"] == ["sql", "summary"]
    assert timeout == 30.0


def test_api_key_only_in_header(http):
    http["result"] = FakeResponse(plan_body(sql="SELECT 1", summary="s"))
    plan()
    request, _ = http["calls"][0]
    assert request.get_header("X-goog-api-key") == KEY
    assert KEY not in request.full_url
    assert KEY not in request.data.decode()


def test_config_from_env_is_used(http):
    http["result"] = FakeResponse(plan_body(sql="SELECT 2", summary="s"))
    planner = GeminiPlanner.from_env(
        {
            "GEMINI_API_KEY": KEY,
            "SQLGUARD_GEMINI_URL": "https://proxy.example/v1/",
            "SQLGUARD_GEMINI_MODEL": "gemini-x-001",
            "SQLGUARD_GEMINI_TIMEOUT_SECONDS": "5",
        }
    )
    plan(planner)
    request, timeout = http["calls"][0]
    assert request.full_url == "https://proxy.example/v1/models/gemini-x-001:generateContent"
    assert planner.model == "gemini-x-001"
    assert timeout == 5.0


@pytest.mark.parametrize(
    "env",
    [
        {},
        {"GEMINI_API_KEY": "  "},
        {"GEMINI_API_KEY": KEY, "SQLGUARD_GEMINI_URL": "http://plain.example"},
        {"GEMINI_API_KEY": KEY, "SQLGUARD_GEMINI_MODEL": "../evil?x=1"},
        {"GEMINI_API_KEY": KEY, "SQLGUARD_GEMINI_TIMEOUT_SECONDS": "abc"},
        {"GEMINI_API_KEY": KEY, "SQLGUARD_GEMINI_TIMEOUT_SECONDS": "0"},
    ],
)
def test_invalid_config(env):
    with pytest.raises(PlannerConfigError):
        GeminiPlanner.from_env(env)


def test_missing_key_names_the_env_var():
    with pytest.raises(PlannerConfigError, match="GEMINI_API_KEY"):
        create_planner({"SQLGUARD_PLANNER": "gemini"})


def test_create_planner_selection():
    planner = create_planner({"SQLGUARD_PLANNER": "gemini", "GEMINI_API_KEY": KEY})
    assert isinstance(planner, GeminiPlanner)
    assert planner.provider == "gemini"


@pytest.mark.parametrize(
    ("failure", "message"),
    [
        (urllib.error.URLError(ConnectionRefusedError()), "connect"),
        (urllib.error.HTTPError("u", 429, "quota", {}, None), "HTTP status 429"),
        (urllib.error.HTTPError("u", 500, "err", {}, None), "HTTP status 500"),
        (TimeoutError(), "timed out"),
        (urllib.error.URLError(TimeoutError()), "timed out"),
    ],
)
def test_transport_failures(http, failure, message):
    http["result"] = failure
    with pytest.raises(PlannerError, match=message) as raised:
        plan()
    assert not isinstance(raised.value, PlannerBlockedError)
    assert KEY not in str(raised.value)


@pytest.mark.parametrize(
    "body",
    [
        json.dumps({"promptFeedback": {"blockReason": "SAFETY"}}).encode(),
        gemini_body("", finish="SAFETY"),
        gemini_body("", finish="PROHIBITED_CONTENT"),
    ],
)
def test_safety_blocks_are_reported_separately(http, body):
    http["result"] = FakeResponse(body)
    with pytest.raises(PlannerBlockedError):
        plan()


@pytest.mark.parametrize(
    ("body", "message"),
    [
        (b"not json", "not valid JSON"),
        (b"[]", "JSON object"),
        (json.dumps({"candidates": []}).encode(), "no candidates"),
        (json.dumps({"candidates": [{"content": {}}]}).encode(), "missing text"),
        (gemini_body("SELECT 1"), "Planner output is not valid JSON"),
        (plan_body(summary="s"), "exactly"),
        (plan_body(sql="SELECT 1", summary="s", extra="x"), "exactly"),
        (plan_body(sql="", summary="s"), "non-empty"),
    ],
)
def test_invalid_responses(http, body, message):
    http["result"] = FakeResponse(body)
    with pytest.raises(PlannerError, match=message):
        plan()


def test_thought_parts_are_ignored(http):
    answer = json.dumps({"sql": "SELECT 1", "summary": "s"})
    thought = {"text": "thinking about DROP TABLE", "thought": True}
    http["result"] = FakeResponse(gemini_body(answer, extra_parts=(thought,)))
    assert plan().sql == "SELECT 1"


def test_same_prompt_as_ollama():
    # Hai provider phải nhận đúng cùng một prompt để so sánh kết quả giữa model là công bằng.
    policy = load_default_policy()
    schema = SchemaContext(
        tables=(SchemaTable(name="orders", columns=(SchemaColumn("id", "integer"),)),)
    )
    feedback = RepairFeedback(
        previous_sql="SELECT secret FROM orders", violation_codes=("x",), guidance="g"
    )
    kwargs = {"schema_context": schema, "policy": policy, "role": "sales"}
    ollama = OllamaPlanner(**kwargs)._build_payload("question", ("note",), feedback)
    remote = gemini(**kwargs)._build_payload("question", ("note",), feedback)

    def strip_nonces(text):
        return re.sub(r"<<(/?)untrusted:([a-z_]+):[0-9a-f]+>>", r"<<\1untrusted:\2>>", text)

    assert remote["systemInstruction"]["parts"][0]["text"] == ollama["messages"][0]["content"]
    assert strip_nonces(remote["contents"][0]["parts"][0]["text"]) == strip_nonces(
        ollama["messages"][1]["content"]
    )


def test_controller_records_blocked_run_without_running_sql(http):
    http["result"] = FakeResponse(gemini_body("", finish="SAFETY"))
    tool = MockQueryTool()
    result = asyncio.run(make_controller(planner=gemini(), tool=tool).run(AgentRequest("Question")))
    assert result.state.status == RunStatus.FAILED
    assert result.state.failure_reason == "planner_blocked"
    assert tool.calls == 0


def test_controller_reports_transport_failure_without_fallback(http):
    http["result"] = urllib.error.URLError(ConnectionRefusedError())
    tool = MockQueryTool()
    result = asyncio.run(make_controller(planner=gemini(), tool=tool).run(AgentRequest("Question")))
    assert result.state.status == RunStatus.FAILED
    assert result.state.failure_reason == "planner_error"
    assert tool.calls == 0


def test_gemini_sql_still_goes_through_gate(http):
    http["result"] = FakeResponse(plan_body(sql="DROP TABLE users", summary="bad"))
    tool = MockQueryTool()
    result = asyncio.run(make_controller(planner=gemini(), tool=tool).run(AgentRequest("Question")))
    assert result.state.status == RunStatus.REFUSED
    assert tool.calls == 0


def test_runtime_builds_gemini_planner_for_role():
    planner = asyncio.run(
        create_planner_for_role("sales", {"SQLGUARD_PLANNER": "gemini", "GEMINI_API_KEY": KEY})
    )
    assert isinstance(planner, GeminiPlanner)
    assert planner._role == "sales"
