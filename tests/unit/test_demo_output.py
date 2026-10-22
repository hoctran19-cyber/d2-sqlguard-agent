import asyncio
import io
import json

import pytest

from sqlguard import demo
from sqlguard.agent import planning
from sqlguard.agent.planning import DemoPlanner, OllamaPlanner, Plan, PlannerConfigError
from sqlguard.mcp.tools import MockQueryTool


class FakeResponse(io.BytesIO):
    def __enter__(self):
        return self

    def __exit__(self, *args):
        self.close()


def mock_ollama(monkeypatch, sql):
    requests = []

    def fake_urlopen(request, timeout=None):
        requests.append(json.loads(request.data))
        content = json.dumps({"sql": sql, "summary": "mocked"})
        return FakeResponse(json.dumps({"message": {"content": content}}).encode())

    monkeypatch.setattr(planning.urllib.request, "urlopen", fake_urlopen)
    return requests


def run(planner=None, **kwargs):
    return asyncio.run(demo.run_demo_report(planner, **kwargs))


def test_planner_selection_from_env(monkeypatch):
    monkeypatch.delenv("SQLGUARD_PLANNER", raising=False)
    assert isinstance(planning.create_planner(), DemoPlanner)
    monkeypatch.setenv("SQLGUARD_PLANNER", "ollama")
    monkeypatch.setenv("SQLGUARD_OLLAMA_MODEL", "custom:model")
    planner = planning.create_planner()
    assert isinstance(planner, OllamaPlanner)
    assert planner.model == "custom:model"


def test_demo_planner_report_shows_sql_gate_and_mock_result():
    report = run(DemoPlanner())
    assert report.succeeded
    assert report.planner == "demo"
    assert report.model is None
    assert [c.sql for c in report.gate_checks] == ["SELECT 1 AS demo_value"]
    assert report.gate_checks[0].allowed
    assert report.tool_sql == ["SELECT 1 AS demo_value"]
    assert report.final_answer == "demo_value=1"
    text = demo.format_report(report)
    assert "planner: demo" in text
    assert "proposed_sql[1]: SELECT 1 AS demo_value" in text
    assert "security_gate[1]: allowed" in text
    assert "MockQueryTool (mock; no database is queried)" in text
    assert "mock_result: demo_value=1" in text


def test_ollama_path_uses_mocked_http_and_shows_generated_sql(monkeypatch):
    requests = mock_ollama(monkeypatch, "SELECT 42 AS answer")
    planner = OllamaPlanner(model="qwen3:1.7b")
    report = run(planner)
    assert len(requests) == 1  # the model is called exactly once
    assert requests[0]["model"] == "qwen3:1.7b"
    assert report.planner == "ollama"
    assert report.model == "qwen3:1.7b"
    assert report.gate_checks[0].sql == "SELECT 42 AS answer"
    assert report.tool_sql == ["SELECT 42 AS answer"]
    text = demo.format_report(report)
    assert "model: qwen3:1.7b" in text
    assert "proposed_sql[1]: SELECT 42 AS answer" in text


def test_rejected_sql_is_reported_and_never_reaches_tool(monkeypatch):
    mock_ollama(monkeypatch, "DROP TABLE users")
    tool = MockQueryTool()
    report = run(OllamaPlanner(model="m"), tool=tool)
    assert not report.succeeded
    assert report.failure_reason == "security_rejection"
    assert report.gate_checks[0].sql == "DROP TABLE users"
    assert not report.gate_checks[0].allowed
    assert report.tool_sql == []
    assert tool.calls == 0
    text = demo.format_report(report)
    assert "security_gate[1]: rejected" in text
    assert "failure_reason: security_rejection" in text
    assert "mock_tool_sql" not in text
    assert "mock_result" not in text


def test_planner_failure_is_reported_without_sql():
    class FailingPlanner:
        async def create_plan(self, question, context):
            raise planning.PlannerError("boom")

    report = run(FailingPlanner())
    assert report.failure_reason == "planner_error"
    assert report.gate_checks == []
    assert "proposed_sql: (none" in demo.format_report(report)


def test_displayed_sql_is_the_sql_given_to_planner_plan():
    class FixedPlanner:
        async def create_plan(self, question, context):
            return Plan(sql="SELECT 7 AS seven", summary="s")

    report = run(FixedPlanner())
    assert report.gate_checks[0].sql == report.tool_sql[0] == "SELECT 7 AS seven"


def test_main_prints_report_and_exit_codes(monkeypatch, capsys):
    monkeypatch.setenv("SQLGUARD_PLANNER", "demo")
    assert demo.main() == 0
    assert "planner: demo" in capsys.readouterr().out

    mock_ollama(monkeypatch, "DELETE FROM t")
    monkeypatch.setenv("SQLGUARD_PLANNER", "ollama")
    assert demo.main() == 1
    assert "security_gate[1]: rejected" in capsys.readouterr().out


def test_main_reports_configuration_error(monkeypatch, capsys):
    monkeypatch.setenv("SQLGUARD_PLANNER", "bogus")
    assert demo.main() == 2
    assert "configuration_error" in capsys.readouterr().err


def test_run_demo_still_returns_final_answer_or_raises(monkeypatch):
    monkeypatch.setenv("SQLGUARD_PLANNER", "demo")
    assert asyncio.run(demo.run_demo()) == "demo_value=1"
    mock_ollama(monkeypatch, "DROP TABLE x")
    monkeypatch.setenv("SQLGUARD_PLANNER", "ollama")
    with pytest.raises(RuntimeError, match="security_rejection"):
        asyncio.run(demo.run_demo())


def test_invalid_planner_config_raises():
    with pytest.raises(PlannerConfigError):
        planning.create_planner({"SQLGUARD_PLANNER": "x"})
