from __future__ import annotations

from collections.abc import Callable
from dataclasses import dataclass
from time import perf_counter

from sqlguard.agent.controller import AgentController
from sqlguard.agent.models import AgentRequest, RunStatus


@dataclass(frozen=True)
class BenchmarkCase:
    case_id: str
    question: str
    expected_status: RunStatus
    expected_answer: str | None = None


@dataclass(frozen=True)
class EvaluationResult:
    case_id: str
    status: str
    passed: bool
    latency_ms: float
    error_category: str | None
    security_decision: str | None
    token_usage: int | None = None
    cost: float | None = None


async def evaluate(
    cases: list[BenchmarkCase], controller_factory: Callable[[], AgentController]
) -> list[EvaluationResult]:
    results = []
    for case in cases:
        controller = controller_factory()
        started = perf_counter()
        run = await controller.run(AgentRequest(case.question))
        latency_ms = (perf_counter() - started) * 1000
        passed = run.state.status == case.expected_status and (
            case.expected_answer is None or run.state.final_answer == case.expected_answer
        )
        results.append(
            EvaluationResult(
                case_id=case.case_id,
                status=run.state.status.value,
                passed=passed,
                latency_ms=latency_ms,
                error_category=run.state.failure_reason,
                security_decision=(
                    "denied"
                    if run.state.failure_reason in {"security_rejection", "db_permission_denied"}
                    else None
                ),
            )
        )
    return results
