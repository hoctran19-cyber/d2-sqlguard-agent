"""Experiment commands for the Financial D2 suite (``python -m evaluation.runner <command>``).

    validate   --experiment FILE                      definitions, snapshot, configs, runtime
    run        --experiment FILE [--tasks ID ...] [--repetitions N] --output DIR
    score      --input DIR                            re-score stored results; no model calls
    summarize  --input DIR                            rebuild summary.csv/json and the report

``run`` refuses to start when ``validate`` has a blocking failure (use ``--force`` to record the
blocked runs as evidence) and ends with a smoke/health check of the written artifacts; a failed
health check returns exit code 1 so a smoke run can gate the full batch.
"""

from __future__ import annotations

import argparse
import asyncio
import copy
import hashlib
import json
import sys
import urllib.error
import urllib.request
from datetime import UTC, datetime
from pathlib import Path

import yaml

from evaluation import financial_runner as fr
from evaluation.financial_adapters import ControllerAdapter, ReplayAdapter
from evaluation.financial_auth_mixed import SuiteValidationError
from evaluation.financial_contract import evaluation_record, result_problems
from evaluation.financial_failure import check_composition
from evaluation.financial_scoring import ConfigContext, score

ROOT = Path(__file__).resolve().parent.parent
DEFAULT_EXPERIMENT = Path(__file__).parent / "experiments" / "d2.yaml"
EXPERIMENT_SCHEMA = "financial-experiment-0.1"
BUDGET_KEYS = {
    "max_sql_attempts",
    "max_retries",
    "max_llm_calls",
    "max_tool_calls",
    "query_timeout_s",
    "run_timeout_s",
}
RECORD_KEYS = {
    "task_id",
    "run_id",
    "config_id",
    "repetition",
    "scorer_version",
    "runtime_status",
    "verdict",
    "checks",
    "failure_reasons",
    "unknown_reasons",
    "trace_ref",
}
OK, WARN, FAIL = "ok", "warn", "fail"


# --------------------------------------------------------------------------------- experiment
def load_experiment(path: Path) -> dict:
    """Parse and structurally check the experiment file; raises ValueError with every problem."""
    path = Path(path)
    document = yaml.safe_load(path.read_text(encoding="utf-8"))
    problems = []
    if not isinstance(document, dict):
        raise ValueError("experiment file must be a mapping")
    if document.get("schema_version") != EXPERIMENT_SCHEMA:
        problems.append(f"schema_version must be {EXPERIMENT_SCHEMA}")
    configs = document.get("configs") or []
    ids = [c.get("id") for c in configs if isinstance(c, dict)]
    if len(configs) != 2 or len(set(ids)) != 2:
        problems.append("exactly two configs with distinct ids are required")
    for config in configs:
        if set((config or {}).get("budget") or {}) != BUDGET_KEYS:
            problems.append(f"{config.get('id')}: budget must define {sorted(BUDGET_KEYS)}")
    repetitions = document.get("repetitions")
    if not isinstance(repetitions, int) or repetitions < 1:
        problems.append("repetitions must be a positive integer")
    elif len(document.get("seeds") or []) < repetitions:
        problems.append("one seed per repetition is required")
    runtime = document.get("runtime") or {}
    if runtime.get("adapter") not in {"controller", "replay"}:
        problems.append("runtime.adapter must be controller or replay")
    snapshot = document.get("snapshot") or {}
    if not snapshot.get("path") or not snapshot.get("sha256"):
        problems.append("snapshot.path and snapshot.sha256 are required")
    if problems:
        raise ValueError("; ".join(problems))
    document["_path"] = str(path)
    document["_sha256"] = hashlib.sha256(path.read_bytes()).hexdigest()
    return document


def runtime_env(experiment: dict) -> dict:
    """Process env plus the experiment's explicit runtime settings (experiment wins)."""
    import os

    runtime = experiment["runtime"]
    env = dict(os.environ)
    mapping = {
        "planner": "SQLGUARD_PLANNER",
        "model": "SQLGUARD_OLLAMA_MODEL",
        "ollama_url": "SQLGUARD_OLLAMA_URL",
        "policy": "SQLGUARD_POLICY",
        "schema_source": "SQLGUARD_SCHEMA_SOURCE",
    }
    for key, name in mapping.items():
        if runtime.get(key) is not None:
            env[name] = str(runtime[key])
    return env


def snapshot_path(experiment: dict) -> Path:
    path = Path(experiment["snapshot"]["path"])
    return path if path.is_absolute() else ROOT / path


def build_adapter(experiment: dict, override: str | None = None):
    kind = override or experiment["runtime"]["adapter"]
    if kind == "replay":
        return ReplayAdapter()
    return ControllerAdapter(
        env=runtime_env(experiment), sqlite_path=str(snapshot_path(experiment))
    )


def configs_doc(experiment: dict) -> dict:
    """The shape ``financial_runner.run_experiment`` expects."""
    return {
        "configs": experiment["configs"],
        "repetitions": experiment["repetitions"],
        "seeds": experiment["seeds"],
        "seed_use": experiment.get("seed_use"),
        "status": f"experiment {experiment['experiment']['name']} "
        f"({Path(experiment['_path']).name} sha256 {experiment['_sha256'][:12]})",
    }


# ----------------------------------------------------------------------------------- validate
def validate(
    experiment: dict, *, adapter_override: str | None = None, tasks: list[str] | None = None
) -> list[tuple[str, str, str]]:
    """Return (check, status, detail) rows; ``fail`` rows block a run."""
    checks = []
    try:
        plans = fr.load_plans()
        problems = check_composition()
        checks.append(
            (
                "definitions",
                FAIL if problems else OK,
                "; ".join(problems) or f"{len(plans)} tasks validated (21 main + 2 clean)",
            )
        )
    except SuiteValidationError as error:
        checks.append(("definitions", FAIL, "; ".join(error.errors[:5])))
        return checks
    known = {p.task_id for p in plans}
    unknown = sorted(set(tasks or []) - known)
    if unknown:
        checks.append(("tasks", FAIL, f"unknown task ids: {unknown}"))
    selected = [p for p in plans if not tasks or p.task_id in tasks]

    path = snapshot_path(experiment)
    actual = fr._sha256_file(path)
    if actual is None:
        checks.append(("snapshot", FAIL, f"{experiment['snapshot']['path']} not found"))
    elif actual != experiment["snapshot"]["sha256"]:
        checks.append(("snapshot", FAIL, f"sha256 {actual[:12]}… differs from the pinned value"))
    else:
        checks.append(("snapshot", OK, f"{experiment['snapshot']['path']} sha256 {actual[:12]}…"))
    for sidecar in ("-wal", "-shm", "-journal"):
        if Path(str(path) + sidecar).exists():
            checks.append(("snapshot", FAIL, f"SQLite sidecar {sidecar} present; snapshot in use"))

    differences = fr.config_differences(experiment["configs"])
    checks.append(
        (
            "configs",
            OK if differences else FAIL,
            "differ in " + ", ".join(differences)
            if differences
            else "configs are identical; no ablation",
        )
    )

    adapter = build_adapter(experiment, adapter_override)
    checks.append(
        (
            "adapter",
            OK if adapter.evidence_mode == "live_runtime" else WARN,
            f"{adapter.name} ({adapter.evidence_mode})"
            + (
                ""
                if adapter.evidence_mode == "live_runtime"
                else " — harness self-test, not a benchmark"
            ),
        )
    )
    if adapter.name == "controller":
        checks += _runtime_checks(experiment, adapter, selected)
    missing = sorted({p.task_id for p in selected if p.requires - adapter.capabilities})
    if missing:
        checks.append(
            ("capabilities", WARN, f"{len(missing)} task(s) will be not_run: {', '.join(missing)}")
        )
    return checks


def _runtime_checks(experiment, adapter, plans) -> list[tuple[str, str, str]]:
    checks = []
    try:
        info = adapter.describe()
    except Exception as error:  # Unknown policy name, unreadable policy file, ...
        return [("runtime_policy", FAIL, f"cannot load policy: {type(error).__name__}")]
    roles = sorted({p.role for p in plans})
    unsupported = [r for r in roles if r not in info["policy_roles"]]
    version = info["policy_version"]
    if unsupported:
        detail = f"policy {version} lacks task role(s) {unsupported}; runs would be infra errors"
    else:
        detail = f"policy {version} defines {roles}"
    checks.append(("runtime_policy", FAIL if unsupported else OK, detail))
    if experiment["runtime"].get("planner") == "ollama":
        url = experiment["runtime"].get("ollama_url", "http://localhost:11434/api/chat")
        tags = url.rsplit("/api/", 1)[0] + "/api/tags"
        try:
            with urllib.request.urlopen(tags, timeout=2) as response:  # noqa: S310 (local URL)
                models = {m.get("name") for m in json.load(response).get("models", [])}
            model = experiment["runtime"].get("model")
            checks.append(
                (
                    "runtime_planner",
                    OK if model in models else FAIL,
                    f"ollama reachable; model {model} "
                    + ("available" if model in models else "not pulled"),
                )
            )
        except (urllib.error.URLError, OSError, ValueError):
            checks.append(("runtime_planner", FAIL, f"ollama not reachable at {tags}"))
    else:
        checks.append(
            (
                "runtime_planner",
                WARN,
                f"planner {experiment['runtime'].get('planner')}"
                " is not an LLM; results do not measure a model",
            )
        )
    return checks


def print_checks(checks) -> None:
    width = max(len(name) for name, _, _ in checks)
    for name, status, detail in checks:
        print(f"[{status.upper():4}] {name.ljust(width)}  {detail}")


# ------------------------------------------------------------------------------- health check
def health_check(output: Path) -> list[tuple[str, str, str]]:
    """Smoke checks on written artifacts: coverage, traces, harness errors, contract shape."""
    output = Path(output)
    manifest = json.loads((output / "manifest.json").read_text(encoding="utf-8"))
    records = fr._read_jsonl(output / "results.jsonl") + fr._read_jsonl(
        output / "clean-pairs.jsonl"
    )
    planned = {
        (task, config["id"], rep)
        for tasks in manifest["tasks"].values()
        for task in tasks
        for config in manifest["configs"]
        for rep in range(1, manifest["repetitions"] + 1)
    }
    recorded = {(r["task_id"], r["config_id"], r["repetition"]) for r in records}
    checks = [
        (
            "coverage",
            OK if planned <= recorded else FAIL,
            f"{len(recorded & planned)}/{len(planned)} planned task-runs recorded",
        )
    ]
    shape = [r["run_id"] for r in records if not RECORD_KEYS <= set(r)]
    checks.append(
        (
            "record_shape",
            FAIL if shape else OK,
            f"{len(shape)} record(s) missing evaluation fields"
            if shape
            else "all records carry the evaluation-record fields",
        )
    )
    traces = [r["run_id"] for r in records if not (output / r["trace_ref"]).is_file()]
    checks.append(
        (
            "traces",
            FAIL if traces else OK,
            f"{len(traces)} missing trace file(s)" if traces else "one trace per record",
        )
    )
    errors = [r for r in records if r["verdict"] == "error"]
    reasons = sorted({x for r in errors for x in r["failure_reasons"]})
    checks.append(
        (
            "harness_errors",
            FAIL if errors else OK,
            f"{len(errors)} run(s): {', '.join(reasons)}" if errors else "none",
        )
    )
    contract = []
    for record in records:
        path = output / record["trace_ref"]
        trace = json.loads(path.read_text(encoding="utf-8")) if path.is_file() else {}
        if "result" in trace and result_problems(trace["result"]):
            contract.append(record["run_id"])
    checks.append(
        (
            "result_contract",
            FAIL if contract else OK,
            f"{len(contract)} result(s) violate financial-result.v1"
            if contract
            else "all runtime results respect financial-result.v1",
        )
    )
    not_run = sum(r["runtime_status"] == "not_run" for r in records)
    checks.append(
        (
            "not_run",
            WARN if not_run else OK,
            f"{not_run} run(s) skipped for missing capabilities" if not_run else "none",
        )
    )
    if not manifest.get("real_benchmark"):
        checks.append(("evidence_mode", WARN, f"{manifest['evidence_mode']} — not a benchmark"))
    return checks


# ---------------------------------------------------------------------------------- re-score
def rescore(output: Path) -> dict:
    """Score every stored runtime result again with the current scorer; never calls a model."""
    output = Path(output)
    manifest = json.loads((output / "manifest.json").read_text(encoding="utf-8"))
    plans = {p.task_id: p for p in fr.load_plans()}
    contexts = {
        c["id"]: ConfigContext(c["id"], c.get("ablation_role"), c["budget"].get("max_retries"))
        for c in manifest["configs"]
    }
    changed, rescored = 0, 0
    for name in ("results.jsonl", "clean-pairs.jsonl"):
        path = output / name
        if not path.exists():
            continue
        lines = []
        for old in fr._read_jsonl(path):
            trace_path = output / old["trace_ref"]
            trace = json.loads(trace_path.read_text(encoding="utf-8"))
            if "result" not in trace:  # not_run / harness error: nothing to score.
                lines.append(old)
                continue
            plan = plans[old["task_id"]]
            if (trace.get("overlay") or {}).get("expected_rows") is not None:
                plan = copy.copy(plan)
                plan.expected_rows = trace["overlay"]["expected_rows"]
            scored = score(plan, trace["result"], contexts[old["config_id"]])
            record = evaluation_record(
                task_id=old["task_id"],
                run_id=old["run_id"],
                config_id=old["config_id"],
                repetition=old["repetition"],
                runtime_status=old["runtime_status"],
                checks=scored["checks"],
                failure_reasons=scored["failures"],
                unknown_reasons=scored["unknown"],
                trace_ref=old["trace_ref"],
            )
            extra = {k: v for k, v in old.items() if k not in RECORD_KEYS}
            record.update(extra)
            changed += record["verdict"] != old["verdict"] or record["checks"] != old["checks"]
            rescored += 1
            trace.update(scoring=scored, record=record)
            fr._write_json(trace_path, trace)
            lines.append(record)
        temporary = path.with_suffix(".jsonl.tmp")
        temporary.write_text(
            "".join(json.dumps(r, ensure_ascii=False, default=str) + "\n" for r in lines),
            encoding="utf-8",
        )
        temporary.replace(path)
    history = manifest.setdefault("scoring_history", [])
    history.append(
        {
            "rescored_at": datetime.now(UTC).isoformat(),
            "scorer_version": fr.SCORER_VERSION,
            "rescored": rescored,
            "changed": changed,
        }
    )
    fr._write_json(output / "manifest.json", manifest)
    return {"rescored": rescored, "changed": changed}


# ---------------------------------------------------------------------------------------- CLI
def _experiment_arg(parser):
    parser.add_argument("--experiment", type=Path, default=DEFAULT_EXPERIMENT)
    parser.add_argument(
        "--adapter",
        choices=["controller", "replay"],
        help="override runtime.adapter (replay = harness self-test)",
    )


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="python -m evaluation.runner", description=__doc__.splitlines()[0]
    )
    sub = parser.add_subparsers(dest="command", required=True)
    check = sub.add_parser("validate", help="check definitions, snapshot and runtime config")
    _experiment_arg(check)
    check.add_argument("--tasks", nargs="+", metavar="TASK_ID")
    run = sub.add_parser("run", help="run tasks and write an experiment directory")
    _experiment_arg(run)
    run.add_argument("--tasks", nargs="+", metavar="TASK_ID", help="default: all 23 tasks")
    run.add_argument("--repetitions", type=int)
    run.add_argument("--output", type=Path, required=True)
    run.add_argument("--resume", action="store_true", help="continue an interrupted run")
    run.add_argument(
        "--force",
        action="store_true",
        help="run even when validate fails (blocked runs are recorded as errors)",
    )
    for name, text in (
        ("score", "re-score stored results without calling a model"),
        ("summarize", "rebuild summary files and error-analysis.md"),
    ):
        item = sub.add_parser(name, help=text)
        item.add_argument("--input", type=Path, required=True)
    return parser


def _blocking(checks) -> bool:
    return any(status == FAIL for _, status, _ in checks)


def main(argv=None) -> int:
    args = build_parser().parse_args(argv)
    if args.command in {"score", "summarize"}:
        if not (args.input / "manifest.json").is_file():
            print(f"no experiment manifest in {args.input}", file=sys.stderr)
            return 2
        if args.command == "score":
            outcome = rescore(args.input)
            print(
                f"re-scored {outcome['rescored']} result(s); {outcome['changed']} changed. "
                "Run summarize to refresh the tables."
            )
            return 0
        summary = fr.write_reports(args.input)
        print(
            json.dumps(
                {
                    "input": str(args.input),
                    "evidence_mode": summary["evidence_mode"],
                    "records": summary["total_records"],
                    "verdicts": summary["verdicts"],
                    "report": str(args.input / "error-analysis.md"),
                },
                indent=2,
            )
        )
        return 0
    try:
        experiment = load_experiment(args.experiment)
    except (OSError, ValueError, yaml.YAMLError) as error:
        print(f"invalid experiment file: {error}", file=sys.stderr)
        return 2
    checks = validate(experiment, adapter_override=args.adapter, tasks=args.tasks)
    print_checks(checks)
    if args.command == "validate":
        return 1 if _blocking(checks) else 0
    if _blocking(checks) and not args.force:
        print(
            "blocked: fix the failed checks or pass --force to record the blocked runs",
            file=sys.stderr,
        )
        return 1
    repetitions = args.repetitions or experiment["repetitions"]
    if not 1 <= repetitions <= len(experiment["seeds"]):
        print(f"--repetitions must be 1..{len(experiment['seeds'])}", file=sys.stderr)
        return 2
    adapter = build_adapter(experiment, args.adapter)
    try:
        summary = asyncio.run(
            fr.run_experiment(
                adapter,
                output=args.output,
                configs_doc=configs_doc(experiment),
                repetitions=repetitions,
                task_ids=set(args.tasks) if args.tasks else None,
                resume=args.resume,
                experiment_ref={
                    "path": Path(experiment["_path"]).name,
                    "sha256": experiment["_sha256"],
                },
            )
        )
    except FileExistsError as error:
        print(f"{error}", file=sys.stderr)
        return 2
    print(
        f"\n{summary['total_records']} record(s) written to {args.output}; "
        f"verdicts {summary['verdicts']}\n"
    )
    health = health_check(args.output)
    print_checks(health)
    return 1 if _blocking(health) else 0
