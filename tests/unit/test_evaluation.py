import asyncio

from tests.conftest import make_controller

from sqlguard.agent.models import RunStatus
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
