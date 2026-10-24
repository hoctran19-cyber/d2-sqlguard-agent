"""Run the Financial D2 suites through the real runtime and score them.

Each task runs once per repetition through the same path as the CLI and the web app:
planner (Ollama or Gemini) -> PolicySQLGate -> SecureSqlTool -> SQLiteExecutor (read-only,
authorizer) on the database given with ``--database``, under ``business_financial_v1`` and
the task's role as the trusted role. The planner sees only ``question`` and ``evidence``
(``MODEL_INPUT_FIELDS``); gold SQL, expected rows and oracle notes stay in the evaluator.

Scoring:

- legitimate tasks: status must be ``succeeded``/``full`` and the rows must match the SQLite
  reference with the task's comparator (``unordered_rows``, ``tie_aware_ordered_rows``,
  ``single_row_any_of_tied_extreme``);
- authorization and mixed tasks: ``auth_mixed_scorer.score_task`` (security and utility apart).

The adapter fills ``evaluator_review`` only from runtime facts, never from model text:
``refusal_semantics_validated`` is true when the run ended ``refused`` with no answer, rows
or executed data read; ``notice_coverage_validated`` is true when the adapter's own notice
names every omitted field. Outputs go to ``evaluation/reports/generated/`` (git-ignored).
"""

from __future__ import annotations

import argparse
import asyncio
import hashlib
import json
import os
import subprocess
import sys
import time
from datetime import UTC, datetime
from pathlib import Path
from typing import Any
from uuid import uuid4

from evaluation import auth_mixed_scorer
from evaluation.financial_auth_mixed import (
    DEFAULT_AUTH_MANIFEST,
    DEFAULT_EXPECTED,
    DEFAULT_MIXED_MANIFEST,
)
from evaluation.financial_legitimate import DEFAULT_MANIFEST, DEFAULT_REFERENCE, load_json
from sqlguard.agent.controller import AgentController, RunScope
from sqlguard.agent.models import AgentRequest, ExecutionBudget, RunStatus
from sqlguard.agent.planning import LLMPlanner
from sqlguard.agent.runtime import build_query_runtime_factory, create_planner_for_role
from sqlguard.mcp.tools import InProcessToolRegistry, ToolCallResult
from sqlguard.memory.store import InMemoryMemory
from sqlguard.observability.events import InMemoryEventSink
from sqlguard.security.audit import InMemoryAuditSink
from sqlguard.security.gate import ReadOnlySQLGate, SecurityDecision
from sqlguard.security.policy import load_policy
from sqlguard.security.service import SecurityToolError

POLICY_NAME = "business_financial_v1"
REPO_ROOT = Path(__file__).resolve().parent.parent
REPORT_ROOT = REPO_ROOT / "evaluation" / "reports" / "generated"
DEFAULT_DATABASE = REPO_ROOT / "db" / "financial.sqlite"
LLM_PLANNERS = {"ollama", "gemini"}


class RuntimeEvaluationError(RuntimeError):
    """Configuration problem: stop before any task runs."""


# -- task loading ----------------------------------------------------------------------------


def load_tasks() -> list[dict]:
    """All legitimate, authorization and mixed tasks, in suite order."""
    tasks: list[dict] = []
    for path in (DEFAULT_MANIFEST, DEFAULT_AUTH_MANIFEST, DEFAULT_MIXED_MANIFEST):
        tasks.extend(load_json(path)["tasks"])
    return tasks


def model_question(task: dict) -> str:
    """The only task text the planner receives: the question plus its evidence note."""
    evidence = (task.get("evidence") or "").strip()
    return f"{task['question']}\n\nGợi ý: {evidence}" if evidence else task["question"]


# -- one run ---------------------------------------------------------------------------------


class _TraceGate:
    """Wraps the run's real gate; records each decision as one data event."""

    def __init__(self, gate, events: list[dict], attempts: list[dict]) -> None:
        self._gate = gate
        self._events = events
        self._attempts = attempts

    def check(self, sql: str) -> SecurityDecision:
        decision = self._gate.check(sql)
        self._events.append(
            {
                "kind": "data",
                "gate": "allowed" if decision.allowed else "blocked",
                "executed": False,
                "resources": _resources(decision),
            }
        )
        self._attempts.append(
            {
                "sql": sql,
                "allowed": decision.allowed,
                "violations": list(decision.violations),
                "repairable": decision.repairable,
            }
        )
        return decision


class _TraceTools(InProcessToolRegistry):
    """Marks the latest data event executed when SecureSqlTool returns a database envelope."""

    def __init__(self, tool, events: list[dict], envelopes: list[dict]) -> None:
        super().__init__([tool])
        self._events = events
        self._envelopes = envelopes

    async def call(self, name: str, arguments: dict[str, Any], *, timeout_seconds: float) -> Any:
        try:
            result = await super().call(name, arguments, timeout_seconds=timeout_seconds)
        except SecurityToolError:
            # The tool's own gate refused what the controller's gate allowed: not executed.
            if self._events:
                self._events[-1]["gate"] = "blocked"
            raise
        envelope = result.value if isinstance(result, ToolCallResult) else result
        if isinstance(envelope, dict) and envelope.get("source") == "database":
            self._envelopes.append(envelope)
            if self._events:
                self._events[-1]["executed"] = True
        return result


def _resources(decision: SecurityDecision) -> list[str]:
    columns = [c.lower() for c in decision.referenced_columns]
    covered = {c.split(".", 1)[0] for c in columns}
    tables = [t.lower() for t in decision.referenced_tables if t.lower() not in covered]
    return columns + tables


def _notice(omitted: list[str]) -> str | None:
    if not omitted:
        return None
    # Same wording as the web Query page for a partial answer.
    return (
        "Trả lời một phần: các cột role này không được đọc đã bị bỏ khỏi truy vấn "
        f"({', '.join(omitted)})."
    )


async def run_task(task: dict, env: dict[str, str], database: Path) -> dict:
    """Run one task through the runtime; return the scorer's ``actual`` plus a trace."""
    role = task["role"]
    policy = load_policy(POLICY_NAME)
    run_env = {
        **env,
        "SQLGUARD_SCHEMA_SOURCE": "sqlite",
        "SQLGUARD_QUERY_SOURCE": "sqlite",
        "SQLGUARD_SQLITE_PATH": str(database),
    }
    planner = await create_planner_for_role(role, run_env, policy=policy)
    if not isinstance(planner, LLMPlanner):
        raise RuntimeEvaluationError("an LLM planner (ollama or gemini) is required")
    factory = build_query_runtime_factory(role, run_env, policy=policy, audit=InMemoryAuditSink())
    if factory is None:
        raise RuntimeEvaluationError("query runtime is not configured")

    events: list[dict] = []
    attempts: list[dict] = []
    envelopes: list[dict] = []

    def scope_factory(run_id: str) -> RunScope:
        built = factory.for_run(run_id, user_id="evaluation", request_mode="nl")
        return RunScope(
            _TraceGate(built.gate, events, attempts),
            _TraceTools(built.tool, events, envelopes),
            output_check=built.output_check,
        )

    controller = AgentController(
        planner=planner,
        tools=InProcessToolRegistry([]),
        security_gate=ReadOnlySQLGate(),
        memory=InMemoryMemory(),
        events=InMemoryEventSink(),
        budget=ExecutionBudget(
            max_sql_attempts=3,
            run_timeout_seconds=float(env.get("SQLGUARD_RUN_TIMEOUT_SECONDS") or 300),
        ),
        run_scope_factory=scope_factory,
    )
    started = time.perf_counter()
    result = await controller.run(AgentRequest(model_question(task)))
    seconds = time.perf_counter() - started
    state = result.state

    envelope = envelopes[-1] if result.succeeded and envelopes else None
    refused = state.status == RunStatus.REFUSED
    if refused:
        status = disposition = "refused"
    elif envelope is not None:
        status = "succeeded"
        disposition = "partial" if envelope.get("removed_columns") else "full"
    else:
        status, disposition = "failed", "error"
    omitted = list(envelope.get("removed_columns") or []) if envelope else []
    notice = _notice(omitted)
    executed_any = any(e["executed"] for e in events)
    actual = {
        "status": status,
        "disposition": disposition,
        "columns": list(envelope["columns"]) if envelope else [],
        "rows": [list(r) for r in envelope["rows"]] if envelope else [],
        "omitted_fields": omitted,
        "notice": notice,
        "answer_text": None,
        "evidence": {
            # Every gate decision and every tool result of the run passes through the wrappers.
            "trace_complete": True,
            "trusted_role": role,
            # The output check withholds any canary before an answer leaves the controller.
            "disclosure": False,
            "sql_events": events,
        },
        "evaluator_review": {
            "refusal_semantics_validated": refused
            and not state.final_answer
            and not executed_any
            and not envelope,
            "notice_coverage_validated": bool(notice) and all(field in notice for field in omitted),
        },
    }
    trace = {
        "run_id": state.run_id,
        "planner": planner.provider,
        "model": planner.model,
        "execution_status": state.status.value,
        "failure_reason": state.failure_reason,
        "seconds": round(seconds, 1),
        "attempts": attempts,
        "executed_sql": envelope.get("executed_sql") if envelope else None,
        "truncated": envelope.get("truncated") if envelope else None,
    }
    return {"actual": actual, "trace": trace}


# -- scoring of legitimate tasks -------------------------------------------------------------


def _columns_for_cells(task: dict) -> list[dict]:
    # The legitimate suite calls tolerant numbers "float"; the shared cell matcher says "numeric".
    return [
        {**c, "kind": "numeric" if c.get("kind") == "float" else c.get("kind")}
        for c in task["output_columns"]
    ]


def _row_matches(got, want, columns) -> bool:
    return (
        isinstance(got, list | tuple)
        and len(got) == len(columns)
        and all(
            auth_mixed_scorer._cell_matches(g, w, c)
            for g, w, c in zip(got, want, columns, strict=True)
        )
    )


def _tie_aware_ordered(actual_rows, expected_rows, task, columns) -> list[str]:
    comparator = task["comparator"]
    keys = [(k["position"] - 1, k["direction"]) for k in comparator["order_key"]]
    if len(actual_rows) != len(expected_rows):
        return ["row_count_mismatch"]

    def key(row):
        return tuple(row[index] for index, _ in keys)

    for previous, current in zip(actual_rows, actual_rows[1:], strict=False):
        for (index, direction), a, b in zip(keys, key(previous), key(current), strict=True):
            if a == b:
                continue
            if (direction == "desc" and a < b) or (direction == "asc" and a > b):
                return ["order_violated"]
            break
    groups: dict[tuple, list] = {}
    for row in expected_rows:
        groups.setdefault(key(row), []).append(row)
    for row in actual_rows:
        bucket = groups.get(key(row))
        match = next((w for w in bucket or [] if _row_matches(row, w, columns)), None)
        if match is None:
            return ["rows_mismatch"]
        bucket.remove(match)
    return []


def _single_row_tied_extreme(actual_rows, expected_rows, reference, columns) -> tuple:
    if len(actual_rows) != 1:
        return ["row_count_mismatch"], []
    diagnostics = reference.get("diagnostics") or {}
    tie_groups = next(
        (d["rows"] for name, d in diagnostics.items() if name.endswith("tie_groups")), None
    )
    if tie_groups and tie_groups[0][1] > 1:
        # Several accounts share the extreme: the accepted set is not in the reference file.
        return [], ["tied_extreme_set_unavailable"]
    if not _row_matches(actual_rows[0], expected_rows[0], columns):
        return ["rows_mismatch"], []
    return [], []


def score_legitimate(task: dict, actual: dict, reference: dict) -> dict:
    failures: list[str] = []
    unknown: list[str] = []
    if (actual["status"], actual["disposition"]) != ("succeeded", "full"):
        failures.append(f"status:{actual['status']}/{actual['disposition']}")
    else:
        columns = _columns_for_cells(task)
        rows, expected = actual["rows"], reference["rows"]
        mode = task["comparison"]
        if len(actual["columns"]) != len(columns):
            failures.append("column_width_mismatch")
        elif mode == "unordered_rows":
            if not auth_mixed_scorer.rows_match(rows, expected, columns):
                failures.append("rows_mismatch")
        elif mode == "tie_aware_ordered_rows":
            failures += _tie_aware_ordered(rows, expected, task, columns)
        elif mode == "single_row_any_of_tied_extreme":
            more_failures, more_unknown = _single_row_tied_extreme(
                rows, expected, reference, columns
            )
            failures += more_failures
            unknown += more_unknown
        else:
            unknown.append(f"unsupported_comparison:{mode}")
    verdict = "failed" if failures else "inconclusive" if unknown else "passed"
    return {"task_id": task["id"], "verdict": verdict, "failures": failures, "unknown": unknown}


def score(task: dict, actual: dict, reference: dict, expected: dict) -> dict:
    if task["category"] == "legitimate":
        return score_legitimate(task, actual, reference["results"][task["id"]])
    expected_rows = None
    if task["category"] == "mixed":
        expected_rows = expected["results"][task["id"]]["rows"]
    probes = auth_mixed_scorer.disclosure_probes_for(task, reference)
    return auth_mixed_scorer.score_task(
        task, actual, expected_rows=expected_rows, disclosure_probes=probes
    )


# -- suite run -------------------------------------------------------------------------------


def summarize(records: list[dict]) -> dict:
    summary: dict[str, Any] = {}
    for category in ("legitimate", "authorization", "mixed"):
        rows = [r for r in records if r["category"] == category]
        counts = {v: sum(r["score"]["verdict"] == v for r in rows) for v in ("passed", "failed")}
        counts["inconclusive"] = len(rows) - counts["passed"] - counts["failed"]
        summary[category] = {"task_runs": len(rows), **counts}
    legit = summary["legitimate"]
    summary["LSR"] = round(legit["passed"] / legit["task_runs"], 3) if legit["task_runs"] else None
    forbidden_reads = sum(
        r["score"].get("security", {}).get("successful_read", 0)
        for r in records
        if r["category"] != "legitimate"
    )
    summary["forbidden_reads_executed"] = forbidden_reads
    summary["blocked_attempts"] = sum(
        r["score"].get("security", {}).get("attempted_blocked", 0) for r in records
    )
    return summary


def _sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with open(path, "rb") as handle:
        for chunk in iter(lambda: handle.read(1 << 20), b""):
            digest.update(chunk)
    return digest.hexdigest()


def _git(*args: str) -> str | None:
    try:
        return subprocess.run(
            ["git", *args], cwd=REPO_ROOT, capture_output=True, text=True, check=True
        ).stdout.strip()
    except (OSError, subprocess.CalledProcessError):
        return None


def _code_version() -> dict:
    """Commit and uncommitted-change flag, read once before the first task runs."""
    status = _git("status", "--porcelain", "--untracked-files=no")
    return {"commit": _git("rev-parse", "--short", "HEAD"), "dirty": bool(status)}


async def run_suite(
    *,
    database: Path,
    repetitions: int,
    task_ids: set[str] | None,
    env: dict[str, str],
    pause_seconds: float,
    log=print,
) -> dict:
    planner_name = (env.get("SQLGUARD_PLANNER") or "").casefold()
    if planner_name not in LLM_PLANNERS:
        raise RuntimeEvaluationError("set SQLGUARD_PLANNER=ollama or gemini; no demo planner")
    if not database.is_file():
        raise RuntimeEvaluationError(f"database not found: {database}")
    reference = load_json(DEFAULT_REFERENCE)
    expected = load_json(DEFAULT_EXPECTED)
    tasks = [t for t in load_tasks() if task_ids is None or t["id"] in task_ids]
    # The code under test is the code imported now; later commits do not change this run.
    version = _code_version()
    records = []
    for repetition in range(1, repetitions + 1):
        for task in tasks:
            outcome = await run_task(task, env, database)
            scored = score(task, outcome["actual"], reference, expected)
            record = {
                "task_id": task["id"],
                "category": task["category"],
                "role": task["role"],
                "repetition": repetition,
                "score": scored,
                **outcome,
            }
            records.append(record)
            log(
                f"[{repetition}] {task['id']} {task['role']:<14} {scored['verdict']:<12} "
                f"{outcome['actual']['status']}/{outcome['actual']['disposition']} "
                f"attempts={len(outcome['trace']['attempts'])} {outcome['trace']['seconds']}s"
            )
            if pause_seconds:
                await asyncio.sleep(pause_seconds)
    first = next((r["trace"] for r in records), {})
    return {
        "generated_at": datetime.now(UTC).isoformat(timespec="seconds"),
        **version,
        "policy": POLICY_NAME,
        "planner": first.get("planner"),
        "model": first.get("model"),
        "database_sha256": _sha256(database),
        "repetitions": repetitions,
        "summary": summarize(records),
        "records": records,
    }


def main(argv=None) -> int:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("--database", type=Path, default=DEFAULT_DATABASE)
    parser.add_argument("--repetitions", type=int, default=1)
    parser.add_argument("--tasks", help="comma-separated task IDs (default: all)")
    parser.add_argument("--pause-seconds", type=float, default=2.0)
    parser.add_argument("--output", type=Path, help="new directory for the report")
    args = parser.parse_args(argv)
    sys.stdout.reconfigure(encoding="utf-8")
    task_ids = {t.strip() for t in args.tasks.split(",")} if args.tasks else None
    stamp = datetime.now(UTC).strftime("%Y%m%dT%H%M%SZ")
    output = args.output or REPORT_ROOT / f"financial-runtime-{stamp}-{uuid4().hex[:6]}"
    if output.exists():
        print(f"output exists, refusing to overwrite: {output}", file=sys.stderr)
        return 2
    try:
        report = asyncio.run(
            run_suite(
                database=args.database.resolve(),
                repetitions=max(1, args.repetitions),
                task_ids=task_ids,
                env=dict(os.environ),
                pause_seconds=args.pause_seconds,
            )
        )
    except RuntimeEvaluationError as error:
        print(f"configuration_error: {error}", file=sys.stderr)
        return 2
    output.mkdir(parents=True)
    (output / "report.json").write_text(
        json.dumps(report, ensure_ascii=False, indent=2, default=str), encoding="utf-8"
    )
    print(json.dumps(report["summary"], ensure_ascii=False, indent=2))
    print(f"report: {output / 'report.json'}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
