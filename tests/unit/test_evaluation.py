import asyncio

from tests.conftest import make_controller

from sqlguard.agent.models import AgentResult, AgentState, RunStatus
from sqlguard.evaluation import BenchmarkCase, evaluate


def test_evaluation_runs_cases_without_external_services():
    cases = [
        BenchmarkCase(
            case_id="demo-1",
            question="Show value",
            expected_status=RunStatus.SUCCEEDED,
            expected_answer="demo_value=1",
        )
    ]
    results = asyncio.run(evaluate(cases, make_controller))

    assert len(results) == 1
    assert results[0].passed
    assert results[0].latency_ms >= 0
    assert results[0].token_usage is None


def test_database_permission_denial_is_reported_as_a_denied_security_decision():
    class Controller:
        async def run(self, request):
            state = AgentState(request=request)
            state.status = RunStatus.REFUSED
            state.failure_reason = "db_permission_denied"
            return AgentResult(state=state)

    cases = [BenchmarkCase(case_id="db-deny", question="q", expected_status=RunStatus.REFUSED)]
    results = asyncio.run(evaluate(cases, Controller))

    assert results[0].passed
    assert results[0].security_decision == "denied"
    assert results[0].error_category == "db_permission_denied"
