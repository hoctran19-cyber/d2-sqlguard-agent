from __future__ import annotations

from dataclasses import dataclass, field
from datetime import UTC, datetime
from enum import StrEnum
from uuid import uuid4


class RunStatus(StrEnum):
    RUNNING = "running"
    SUCCEEDED = "succeeded"
    REFUSED = "refused"
    FAILED = "failed"
    TIMED_OUT = "timed_out"
    BUDGET_EXHAUSTED = "budget_exhausted"


@dataclass(frozen=True)
class AgentRequest:
    question: str
    run_id: str | None = None


@dataclass(frozen=True)
class ExecutionBudget:
    max_retries: int = 3
    max_llm_calls: int = 6
    max_tool_calls: int = 8
    query_timeout_seconds: float = 3.0
    run_timeout_seconds: float = 60.0
    max_sql_attempts: int | None = None

    def __post_init__(self) -> None:
        if min(self.max_retries, self.max_llm_calls, self.max_tool_calls) < 0:
            raise ValueError("Call and retry limits cannot be negative")
        if self.max_sql_attempts is not None and self.max_sql_attempts < 0:
            raise ValueError("SQL attempt limit cannot be negative")
        if self.query_timeout_seconds <= 0 or self.run_timeout_seconds <= 0:
            raise ValueError("Timeouts must be positive")


@dataclass
class AgentState:
    request: AgentRequest
    run_id: str = field(default_factory=lambda: str(uuid4()))
    current_step: str = "created"
    status: RunStatus = RunStatus.RUNNING
    tool_call_count: int = 0
    llm_call_count: int = 0
    retry_count: int = 0
    errors: list[str] = field(default_factory=list)
    final_answer: str | None = None
    failure_reason: str | None = None
    started_at: datetime = field(default_factory=lambda: datetime.now(UTC))
    finished_at: datetime | None = None
    sql_attempt_count: int = 0
    active_sql_attempt_id: str | None = None
    related_sql_attempt_id: str | None = None

    def __post_init__(self) -> None:
        if self.request.run_id is not None:
            self.run_id = self.request.run_id


@dataclass(frozen=True)
class AgentResult:
    state: AgentState

    @property
    def succeeded(self) -> bool:
        return self.state.status == RunStatus.SUCCEEDED
