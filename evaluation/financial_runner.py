"""Unified Financial D2 runner: prepare every task group, run it through an adapter, score each
task-run by category and write one experiment directory.

    python -m evaluation.financial_runner --adapter replay      # harness self-test
    python -m evaluation.financial_runner --adapter controller  # packaged runtime

Artifacts (``evaluation/reports/generated/<experiment-id>/`` by default, never overwritten)::

    manifest.json  results.jsonl  usage.jsonl  clean-pairs.jsonl  traces/
    summary.csv  summary.json  error-analysis.md

``results.jsonl`` holds the main tasks (21), ``clean-pairs.jsonl`` the clean controls paired with
the injection run of the same config and repetition. A task that needs a capability the adapter
lacks (fault hook, injection overlay) is recorded as ``not_run``: coverage, not a model result.
"""

from __future__ import annotations

import argparse
import asyncio
import copy
import csv
import hashlib
import json
import math
import random
import statistics
import subprocess
import sys
from collections import Counter, defaultdict
from datetime import UTC, datetime
from pathlib import Path
from uuid import uuid4

import yaml

from evaluation import auth_mixed_scorer as ams
from evaluation import financial_auth_mixed as fam
from evaluation import financial_failure as ff
from evaluation import financial_injection as fi
from evaluation import financial_legitimate as fl
from evaluation.financial_adapters import (
    CAP_FAULT_HOOK,
    CAP_INJECTION_OVERLAY,
    DEFAULT_SQLITE_PATH,
    AdapterUnavailable,
    ControllerAdapter,
    ReplayAdapter,
    RunRequest,
)
from evaluation.financial_contract import CONTRACT_VERSION, SCORER_VERSION, evaluation_record
from evaluation.financial_scoring import ConfigContext, TaskPlan, error_category, score

ROOT = Path(__file__).resolve().parent.parent
DEFAULT_CONFIGS = Path(__file__).parent / "experiments" / "d2.yaml"
DEFAULT_OUTPUT_DIR = Path(__file__).parent / "reports" / "generated"
CATEGORY_ORDER = ("legitimate", "authorization", "mixed", "injection", "failure", "clean")
HARNESS_GRACE_S = 5.0
VERDICT_LETTER = {"passed": "P", "failed": "F", "inconclusive": "I", "error": "E"}


# ------------------------------------------------------------------------------------ planning
def load_plans() -> list[TaskPlan]:
    """Validate every component manifest and resolve evaluator-side expectations per task."""
    legitimate = fl.load_suite()
    reference = fl.load_json(fl.DEFAULT_REFERENCE)
    auth, mixed, am_artifact, _ = fam.load_all()
    injection, clean, inj_artifact, _ = fi.load_all()
    failure = ff.load_suite()
    errors = ff.check_composition()
    if errors:
        raise fam.SuiteValidationError(errors)
    allowlists = legitimate["policy"]["allowlists"]
    questions = {item["id"]: item["question"] for item in fi.public_inputs(injection)}
    plans = []

    def plan(task, category, **kwargs):
        allow = fam.role_allow(allowlists, task["role"])
        if category == "injection":
            task = dict(task, question=questions[task["id"]])
        plans.append(TaskPlan(task=task, category=category, allow=allow, **kwargs))

    for task in legitimate["tasks"]:
        ref = reference["results"][task["id"]]
        ties = [d for name, d in (ref.get("diagnostics") or {}).items() if "tie_groups" in name]
        tie_count = ties[0]["rows"][0][1] if ties and ties[0].get("rows") else None
        plan(task, "legitimate", expected_rows=ref["rows"], tie_count=tie_count)
    for task in auth["tasks"]:
        plan(task, "authorization", disclosure_probes=ams.disclosure_probes_for(task, reference))
    for task in mixed["tasks"]:
        plan(task, "mixed", expected_rows=am_artifact["results"][task["id"]]["rows"])
    for task in injection["tasks"]:
        if task["attack"]["surface"] == "direct":
            plan(task, "injection", expected_rows=inj_artifact["results"][task["id"]]["rows"])
        else:  # Expected rows come from the per-run overlay prepared at run time.
            plan(task, "injection", requires=frozenset({CAP_INJECTION_OVERLAY}))
    for task in failure["tasks"]:
        base = ff.TASKS[task["id"]]["base"]
        rows = reference["results"][base]["rows"]
        if task["id"] == "D2-F01":
            plan(task, "failure", expected_rows=rows, requires=frozenset({CAP_FAULT_HOOK}))
        else:
            values = [str(c) for row in rows for c in row if c is not None]
            plan(task, "failure", forbidden_values=values, requires=frozenset({CAP_FAULT_HOOK}))
    attacked = {t["id"]: t for t in injection["tasks"]}
    for task in clean["tasks"]:
        paired = fi.CLEAN_TASKS[task["id"]]
        # Clean controls share the output shape of their injection task (not repeated there).
        shape = {k: attacked[paired][k] for k in ("output_columns", "comparison")}
        plan(
            dict(task, **shape),
            "clean",
            expected_rows=inj_artifact["results"][paired]["baseline"]["rows"],
        )
    plans.sort(key=lambda p: CATEGORY_ORDER.index(p.category))
    return plans


def load_configs(path: Path = DEFAULT_CONFIGS) -> dict:
    """Configs, repetitions and seeds from the experiment file (YAML; JSON is valid YAML)."""
    document = yaml.safe_load(Path(path).read_text(encoding="utf-8"))
    configs = document.get("configs") or []
    ids = [c.get("id") for c in configs]
    if len(configs) != 2 or len(set(ids)) != 2:
        raise ValueError("exactly two distinct configs are required")
    keys = {
        "max_sql_attempts",
        "max_retries",
        "max_llm_calls",
        "max_tool_calls",
        "query_timeout_s",
        "run_timeout_s",
    }
    for config in configs:
        if set(config.get("budget") or {}) != keys:
            raise ValueError(f"{config.get('id')}: budget must define {sorted(keys)}")
    if len(document.get("seeds") or []) < document.get("repetitions", 0):
        raise ValueError("one seed per repetition is required")
    return document


def config_differences(configs: list[dict]) -> dict:
    """Fields whose value differs between the two configs (the declared ablation)."""
    left, right = configs
    flat = {}
    for key in ("ablation_role",):
        flat[key] = (left.get(key), right.get(key))
    for key in left["budget"]:
        flat[f"budget.{key}"] = (left["budget"][key], right["budget"][key])
    return {k: {left["id"]: a, right["id"]: b} for k, (a, b) in flat.items() if a != b}


# ----------------------------------------------------------------------------------- metadata
def _sha256_file(path: Path) -> str | None:
    if not path.is_file():
        return None
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        for block in iter(lambda: stream.read(1 << 20), b""):
            digest.update(block)
    return digest.hexdigest()


def _git() -> dict:
    try:
        commit = subprocess.check_output(
            ["git", "rev-parse", "HEAD"], cwd=ROOT, text=True, stderr=subprocess.DEVNULL
        ).strip()
        dirty = bool(
            subprocess.check_output(
                ["git", "status", "--porcelain"], cwd=ROOT, text=True, stderr=subprocess.DEVNULL
            ).strip()
        )
        return {"commit": commit, "dirty": dirty}
    except (OSError, subprocess.CalledProcessError):
        return {"commit": None, "dirty": None}


def _implementation_sha256() -> str:
    digest = hashlib.sha256()
    for path in sorted(
        [
            *(ROOT / "evaluation").glob("financial_*.py"),
            ROOT / "evaluation" / "auth_mixed_scorer.py",
            *(ROOT / "src" / "sqlguard").rglob("*.py"),
        ]
    ):
        digest.update(str(path.relative_to(ROOT)).encode())
        digest.update(path.read_bytes())
    return digest.hexdigest()


def build_manifest(
    experiment_id, adapter, configs_doc, plans, repetitions, seeds, experiment_ref=None
) -> dict:
    suite_files = sorted(fl.SUITE_DIR.glob("*.v0.1.json")) + sorted(
        (fl.SUITE_DIR / "expected").glob("*.json")
    )
    adapter_info = adapter.describe()
    snapshot = Path(getattr(adapter, "sqlite_path", DEFAULT_SQLITE_PATH))
    return {
        "experiment_id": experiment_id,
        "created_at": datetime.now(UTC).isoformat(),
        "suite_id": fl.SUITE_ID,
        "experiment_file": experiment_ref,
        "contract_version": CONTRACT_VERSION,
        "scorer_version": SCORER_VERSION,
        "adapter": adapter_info,
        "evidence_mode": adapter.evidence_mode,
        "real_benchmark": adapter.evidence_mode == "live_runtime",
        **_git(),
        "implementation_sha256": _implementation_sha256(),
        "task_manifests": {str(p.relative_to(fl.SUITE_DIR)): _sha256_file(p) for p in suite_files},
        "snapshot": {
            "path": "data/bird/financial.sqlite"
            if snapshot.resolve() == DEFAULT_SQLITE_PATH.resolve()
            else "configured",
            "sha256": _sha256_file(snapshot),
        },
        "configs": configs_doc["configs"],
        "config_differences": config_differences(configs_doc["configs"]),
        "config_status": configs_doc.get("status"),
        "repetitions": repetitions,
        "seeds": seeds[:repetitions],
        "seed_use": configs_doc.get("seed_use"),
        "tasks": {c: [p.task_id for p in plans if p.category == c] for c in CATEGORY_ORDER},
        "planned_runs": {
            "main": sum(p.category != "clean" for p in plans)
            * len(configs_doc["configs"])
            * repetitions,
            "clean": sum(p.category == "clean" for p in plans)
            * len(configs_doc["configs"])
            * repetitions,
        },
        "concurrency": 1,
        "latency_scope": "adapter call (planner, gate, tool, database); excludes scoring and I/O",
        "limitations": [
            "harness_selftest results come from the evaluator oracle and are not a benchmark",
            "token usage is null when the runtime does not report it (unknown, never 0)",
            "fault hooks and injection overlays run only when the adapter declares them",
            "auth/mixed utility needs trusted evaluator review evidence; missing -> inconclusive",
        ],
    }


# ---------------------------------------------------------------------------------- execution
def _write_json(path: Path, value) -> None:
    path.write_text(
        json.dumps(value, ensure_ascii=False, indent=2, default=str) + "\n", encoding="utf-8"
    )


def _not_run_record(plan, config, repetition, run_id, missing) -> dict:
    checks = {"utility": "not_run", "security": "not_run"}
    if plan.category == "injection":
        checks["attack"] = "not_run"
    if plan.category == "failure":
        checks["recovery"] = "not_run"
    return evaluation_record(
        task_id=plan.task_id,
        run_id=run_id,
        config_id=config["id"],
        repetition=repetition,
        runtime_status="not_run",
        checks=checks,
        failure_reasons=[],
        unknown_reasons=[f"capability_missing:{m}" for m in sorted(missing)],
        trace_ref=f"traces/{run_id}.json",
    )


async def run_one(adapter, plan, config, repetition, run_id) -> tuple[dict, dict, dict]:
    """Return (evaluation record, usage line, trace document) for one task-run."""
    trace_ref = f"traces/{run_id}.json"
    trace = {
        "run_id": run_id,
        "task_id": plan.task_id,
        "category": plan.category,
        "config_id": config["id"],
        "repetition": repetition,
        "model_input": {
            "role": plan.role,
            "question": plan.task["question"],
            "evidence": plan.task["evidence"],
        },
    }
    usage = {
        "run_id": run_id,
        "task_id": plan.task_id,
        "config_id": config["id"],
        "repetition": repetition,
        "evidence_mode": adapter.evidence_mode,
    }
    missing = plan.requires - adapter.capabilities
    if missing:
        record = _not_run_record(plan, config, repetition, run_id, missing)
        trace["outcome"] = "not_run"
        usage.update(latency_ms=None, usage=None, counters=None)
        return record, usage, trace
    if CAP_INJECTION_OVERLAY in plan.requires:
        overlay = fi.prepare_overlay(plan.task, fi.load_all()[2], fi.new_nonce())
        plan = copy.copy(plan)
        plan.expected_rows = overlay["expected_rows"]
        trace["overlay"] = {
            "marker": overlay["marker"],
            "patch": overlay["patch"],
            "expected_rows": overlay["expected_rows"],  # Kept so `score` can re-score offline.
        }
    else:
        overlay = None
    request = RunRequest(
        run_id=run_id,
        task_id=plan.task_id,
        role=plan.role,
        question=plan.task["question"],
        evidence=plan.task["evidence"],
        config=config,
        fault=plan.task.get("fault"),
        overlay=overlay,
    )
    context = ConfigContext(
        config["id"], config.get("ablation_role"), config["budget"].get("max_retries")
    )
    timeout = config["budget"]["run_timeout_s"] + HARNESS_GRACE_S
    try:
        output = await asyncio.wait_for(adapter.run(request, plan), timeout=timeout)
    except AdapterUnavailable as error:
        return _error(
            plan,
            config,
            repetition,
            run_id,
            f"evaluation_infrastructure:{error.category}",
            trace,
            usage,
        )
    except TimeoutError:
        return _error(
            plan,
            config,
            repetition,
            run_id,
            "evaluation_infrastructure:harness_timeout",
            trace,
            usage,
        )
    except Exception as error:  # Harness/runtime crash: never a model failure, never a pass.
        return _error(
            plan,
            config,
            repetition,
            run_id,
            f"evaluation_infrastructure:{type(error).__name__}",
            trace,
            usage,
        )
    result = dict(output.result, trace_ref=trace_ref)
    scored = score(plan, result, context)
    record = evaluation_record(
        task_id=plan.task_id,
        run_id=run_id,
        config_id=config["id"],
        repetition=repetition,
        runtime_status=str(result.get("status")),
        checks=scored["checks"],
        failure_reasons=scored["failures"],
        unknown_reasons=scored["unknown"],
        trace_ref=trace_ref,
    )
    trace.update(result=result, scoring=scored, runtime_trace=output.trace)
    usage.update(latency_ms=output.latency_ms, usage=output.usage, counters=output.counters)
    return record, usage, trace


def _error(plan, config, repetition, run_id, reason, trace, usage):
    record = evaluation_record(
        task_id=plan.task_id,
        run_id=run_id,
        config_id=config["id"],
        repetition=repetition,
        runtime_status="harness_error",
        checks={},
        failure_reasons=[reason],
        unknown_reasons=[],
        trace_ref=f"traces/{run_id}.json",
        verdict="error",
    )
    trace["outcome"] = reason
    usage.update(latency_ms=None, usage=None, counters=None)
    return record, usage, trace


def _annotate(record: dict, plan, seed: int, usage: dict) -> dict:
    """Runner metadata kept next to (not inside) the evaluation record fields."""
    return {
        **record,
        "run": {
            "category": plan.category,
            "role": plan.role,
            "seed": seed,
            "latency_ms": usage.get("latency_ms"),
            "counters": usage.get("counters"),
        },
    }


async def run_experiment(
    adapter,
    *,
    output: Path,
    configs_doc: dict,
    repetitions: int | None = None,
    task_ids: set[str] | None = None,
    resume: bool = False,
    experiment_ref: dict | None = None,
) -> dict:
    plans = [p for p in load_plans() if not task_ids or p.task_id in task_ids]
    repetitions = repetitions or configs_doc["repetitions"]
    seeds = configs_doc["seeds"]
    output = Path(output)
    if output.exists() and not resume:
        raise FileExistsError(f"{output} exists; use a new directory or --resume")
    (output / "traces").mkdir(parents=True, exist_ok=True)
    experiment_id = output.name
    manifest_path = output / "manifest.json"
    if not manifest_path.exists():
        _write_json(
            manifest_path,
            build_manifest(
                experiment_id, adapter, configs_doc, plans, repetitions, seeds, experiment_ref
            ),
        )
    done = set()
    for name in ("results.jsonl", "clean-pairs.jsonl"):
        path = output / name
        if resume and path.exists():
            for line in path.read_text(encoding="utf-8").splitlines():
                row = json.loads(line)
                done.add((row["task_id"], row["config_id"], row["repetition"]))
    by_id = {p.task_id: p for p in plans}
    with (
        (output / "results.jsonl").open("a", encoding="utf-8") as results,
        (output / "clean-pairs.jsonl").open("a", encoding="utf-8") as pairs,
        (output / "usage.jsonl").open("a", encoding="utf-8") as usage_file,
    ):
        for repetition in range(1, repetitions + 1):
            seed = seeds[repetition - 1]
            for config in configs_doc["configs"]:
                order = sorted(by_id)
                random.Random(seed).shuffle(order)
                for task_id in order:
                    if (task_id, config["id"], repetition) in done:
                        continue
                    plan = by_id[task_id]
                    run_id = f"{experiment_id}-{config['id']}-r{repetition}-{task_id}"
                    record, usage, trace = await run_one(adapter, plan, config, repetition, run_id)
                    record = _annotate(record, plan, seed, usage)
                    if plan.category == "clean":
                        paired = fi.CLEAN_TASKS[task_id]
                        record["pair"] = {
                            "injection_task": paired,
                            "injection_run_id": f"{experiment_id}-{config['id']}-r{repetition}"
                            f"-{paired}",
                        }
                        target = pairs
                    else:
                        target = results
                    _write_json(output / record["trace_ref"], dict(trace, record=record))
                    target.write(json.dumps(record, ensure_ascii=False, default=str) + "\n")
                    target.flush()
                    usage_file.write(json.dumps(usage, ensure_ascii=False, default=str) + "\n")
                    usage_file.flush()
    return write_reports(output)


# -------------------------------------------------------------------------------- aggregation
def _read_jsonl(path: Path) -> list[dict]:
    if not path.exists():
        return []
    return [json.loads(line) for line in path.read_text(encoding="utf-8").splitlines() if line]


def _mean_sd(values: list[float]) -> tuple[float | None, float | None]:
    if not values:
        return None, None
    mean = statistics.fmean(values)
    return mean, (statistics.stdev(values) if len(values) > 1 else None)


def _fmt_pct(mean, sd) -> str:
    if mean is None:
        return "—"
    return f"{mean * 100:.1f}%" + (f" ± {sd * 100:.1f} pp" if sd is not None else "")


def _percentile(values: list[float], q: float) -> float | None:
    if not values:
        return None
    ordered = sorted(values)
    index = min(len(ordered) - 1, max(0, math.ceil(q * len(ordered)) - 1))
    return ordered[index]


def aggregate(manifest: dict, records: list[dict], usage: list[dict]) -> dict:
    configs = [c["id"] for c in manifest["configs"]]
    reps = manifest["repetitions"]
    tasks = manifest["tasks"]
    by_key = defaultdict(list)
    for record in records:
        by_key[(record["config_id"], record["run"]["category"])].append(record)

    configuration = {
        "adapter": manifest["adapter"],
        "evidence_mode": manifest["evidence_mode"],
        "real_benchmark": manifest["real_benchmark"],
        "snapshot": manifest["snapshot"],
        "policy": manifest["adapter"].get("policy_version"),
        "configs": manifest["configs"],
        "differences": manifest["config_differences"],
        "repetitions": reps,
        "seeds": manifest["seeds"],
    }

    coverage = []
    for config in configs:
        for category in CATEGORY_ORDER:
            if not tasks.get(category):
                continue
            rows = by_key[(config, category)]
            planned = len(tasks[category]) * reps
            completed = sum(
                r["verdict"] != "error" and r["runtime_status"] != "not_run" for r in rows
            )
            missing_run = sum(r["runtime_status"] == "not_run" for r in rows)
            coverage.append(
                {
                    "config_id": config,
                    "category": category,
                    "planned": planned,
                    "completed": completed,
                    "not_run": missing_run,
                    "missing": planned - len(rows),
                    "error": sum(r["verdict"] == "error" for r in rows),
                }
            )

    main = []
    for config in configs:
        for category in CATEGORY_ORDER:
            if not tasks.get(category):
                continue
            rows = by_key[(config, category)]
            n_tasks = len(tasks[category])
            per_rep = []
            for rep in range(1, reps + 1):
                counts = Counter(r["verdict"] for r in rows if r["repetition"] == rep)
                per_rep.append(counts)
            rates = [c["passed"] / n_tasks for c in per_rep if sum(c.values())]
            mean, sd = _mean_sd(rates)
            main.append(
                {
                    "config_id": config,
                    "category": category,
                    "tasks": n_tasks,
                    "passed_per_rep": [c["passed"] for c in per_rep],
                    "failed_per_rep": [c["failed"] for c in per_rep],
                    "inconclusive_per_rep": [c["inconclusive"] for c in per_rep],
                    "error_per_rep": [c["error"] for c in per_rep],
                    "pass_rate_mean": mean,
                    "pass_rate_sd": sd,
                    "pass_rate": _fmt_pct(mean, sd),
                }
            )

    security = []
    for config in configs:
        rows = [r for (c, _), rs in by_key.items() if c == config for r in rs]

        def count(pred, pool, rows=rows):
            pool_rows = [r for r in rows if r["run"]["category"] in pool]
            return {"numerator": sum(pred(r) for r in pool_rows), "runs": len(pool_rows)}

        unauthorized = count(
            lambda r: any(
                x.startswith(("forbidden_read", "disclosure")) for x in r["failure_reasons"]
            ),
            {"authorization", "mixed", "injection", "legitimate", "clean", "failure"},
        )
        security.append(
            {
                "config_id": config,
                "unauthorized_access_or_disclosure": unauthorized,
                "attack_success": count(lambda r: r["checks"]["attack"] == "failed", {"injection"}),
                "attack_inconclusive": count(
                    lambda r: r["checks"]["attack"] in {"inconclusive", "not_run"}, {"injection"}
                ),
                "recovery_passed": count(
                    lambda r: r["checks"]["recovery"] == "passed", {"failure"}
                ),
            }
        )

    per_task = []
    for category in CATEGORY_ORDER:
        for task_id in tasks.get(category, []):
            row = {"task_id": task_id, "category": category}
            for config in configs:
                letters = []
                for rep in range(1, reps + 1):
                    match = [
                        r
                        for r in records
                        if r["task_id"] == task_id
                        and r["config_id"] == config
                        and r["repetition"] == rep
                    ]
                    if not match:
                        letters.append("-")
                    elif match[0]["runtime_status"] == "not_run":
                        letters.append("N")
                    else:
                        letters.append(VERDICT_LETTER[match[0]["verdict"]])
                row[config] = " ".join(letters)
            per_task.append(row)

    errors = defaultdict(
        lambda: {"runs": set(), "tasks": set(), "reasons": Counter(), "traces": []}
    )
    for record in records:
        reasons = record["failure_reasons"] + (
            record["unknown_reasons"] if record["verdict"] == "inconclusive" else []
        )
        for reason in reasons:
            if reason.startswith("capability_missing"):
                category = "not_run"
            elif reason in record["failure_reasons"]:
                category = error_category(reason)
            elif "pending" in reason:
                category = "contract_pending"  # Open contract decision, not missing evidence.
            else:
                category = "missing_evidence"
            entry = errors[category]
            entry["runs"].add(record["run_id"])
            entry["tasks"].add(record["task_id"])
            entry["reasons"][reason] += 1
            if len(entry["traces"]) < 3 and record["trace_ref"] not in entry["traces"]:
                entry["traces"].append(record["trace_ref"])
    error_analysis = [
        {
            "error_category": category,
            "runs": len(v["runs"]),
            "task_ids": sorted(v["tasks"]),
            "top_reasons": [f"{k} ×{n}" for k, n in v["reasons"].most_common(4)],
            "sample_traces": v["traces"],
        }
        for category, v in sorted(errors.items(), key=lambda item: -len(item[1]["runs"]))
    ]

    efficiency = []
    for config in configs:
        lines = [u for u in usage if u["config_id"] == config and u.get("latency_ms") is not None]
        latency = [u["latency_ms"] for u in lines]
        counters = [u.get("counters") or {} for u in lines]
        usages = [u.get("usage") or {} for u in lines]

        def mean_of(values):
            known = [v for v in values if isinstance(v, int | float)]
            return (statistics.fmean(known), len(known)) if known else (None, 0)

        tokens = [
            (u.get("input_tokens") or 0) + (u.get("output_tokens") or 0)
            for u in usages
            if u.get("input_tokens") is not None
        ]
        efficiency.append(
            {
                "config_id": config,
                "runs_with_timing": len(lines),
                "latency_ms_mean": statistics.fmean(latency) if latency else None,
                "latency_ms_median": statistics.median(latency) if latency else None,
                "latency_ms_p95": _percentile(latency, 0.95),
                "planner_calls_mean": mean_of([c.get("planner_calls") for c in counters])[0],
                "tool_calls_mean": mean_of([c.get("tool_calls") for c in counters])[0],
                "sql_attempts_mean": mean_of([c.get("sql_attempts") for c in counters])[0],
                "tokens_total": sum(tokens) if tokens else None,
                "token_coverage": f"{len(tokens)}/{len(lines)} runs reported tokens",
                "cost_usd_total": sum(
                    u["cost_usd"] for u in usages if isinstance(u.get("cost_usd"), int | float)
                )
                if any(isinstance(u.get("cost_usd"), int | float) for u in usages)
                else None,
            }
        )

    return {
        "experiment_id": manifest["experiment_id"],
        "evidence_mode": manifest["evidence_mode"],
        "real_benchmark": manifest["real_benchmark"],
        "total_records": len(records),
        "verdicts": dict(Counter(r["verdict"] for r in records)),
        "tables": {
            "experiment_configuration": configuration,
            "run_coverage": coverage,
            "main_results": main,
            "security_metrics": security,
            "per_task_results": per_task,
            "error_analysis": error_analysis,
            "efficiency": efficiency,
        },
    }


# ----------------------------------------------------------------------------------- reporting
SUMMARY_FIELDS = (
    "task_id",
    "category",
    "role",
    "config_id",
    "repetition",
    "seed",
    "runtime_status",
    "verdict",
    "utility",
    "security",
    "attack",
    "recovery",
    "failure_reasons",
    "unknown_reasons",
    "latency_ms",
    "planner_calls",
    "tool_calls",
    "sql_attempts",
    "run_id",
    "trace_ref",
)


def _summary_row(record: dict) -> dict:
    counters = record["run"].get("counters") or {}
    return {
        "task_id": record["task_id"],
        "category": record["run"]["category"],
        "role": record["run"]["role"],
        "config_id": record["config_id"],
        "repetition": record["repetition"],
        "seed": record["run"]["seed"],
        "runtime_status": record["runtime_status"],
        "verdict": record["verdict"],
        **record["checks"],
        "failure_reasons": ";".join(record["failure_reasons"]),
        "unknown_reasons": ";".join(record["unknown_reasons"]),
        "latency_ms": record["run"].get("latency_ms"),
        "planner_calls": counters.get("planner_calls"),
        "tool_calls": counters.get("tool_calls"),
        "sql_attempts": counters.get("sql_attempts"),
        "run_id": record["run_id"],
        "trace_ref": record["trace_ref"],
    }


def _md_table(headers: list[str], rows: list[list]) -> str:
    def cell(value):
        if value is None:
            return "—"
        if isinstance(value, float):
            return f"{value:.1f}"
        return str(value).replace("|", "\\|")

    lines = ["| " + " | ".join(headers) + " |", "|" + "---|" * len(headers)]
    lines += ["| " + " | ".join(cell(v) for v in row) + " |" for row in rows]
    return "\n".join(lines)


def _bar_chart(
    title: str,
    labels: list[str],
    series: dict[str, list[float]],
    y_label: str,
    y_max: float | None = None,
) -> str:
    """Mermaid xychart (renders on GitHub/most Markdown viewers); one bar series per config."""
    top = y_max if y_max is not None else max([v for s in series.values() for v in s] + [1.0])
    lines = [
        "```mermaid",
        "xychart-beta",
        f'    title "{title}"',
        "    x-axis [" + ", ".join(f'"{label}"' for label in labels) + "]",
        f'    y-axis "{y_label}" 0 --> {top:.0f}',
    ]
    for values in series.values():
        lines.append("    bar [" + ", ".join(f"{v:.1f}" for v in values) + "]")
    lines.append("```")
    legend = ", ".join(f"bar {i + 1} = {name}" for i, name in enumerate(series))
    return "\n".join(lines) + f"\n\n_Series: {legend}._"


def render_report(summary: dict) -> str:
    t = summary["tables"]
    conf = t["experiment_configuration"]
    configs = [c["id"] for c in conf["configs"]]
    out = [f"# Experiment {summary['experiment_id']} — results and error analysis", ""]
    if not summary["real_benchmark"]:
        out += [
            f"> **Evidence mode: `{summary['evidence_mode']}` — not a benchmark result.** "
            "Numbers below only check the runner, scorers and reports.",
            "",
        ]
    incomplete = [r for r in t["run_coverage"] if r["completed"] < r["planned"]]
    if incomplete:
        out += [
            "> **Incomplete coverage:** "
            f"{sum(r['planned'] - r['completed'] for r in incomplete)} planned task-runs were "
            "not completed (not run, harness error or missing). Rates below use all planned "
            "tasks as the denominator; see section 2.",
            "",
        ]
    out += ["## 1. Experiment configuration", ""]
    out.append(
        _md_table(
            ["Item", "Value"],
            [
                [
                    "Adapter / evidence mode",
                    f"{conf['adapter'].get('adapter')} / {conf['evidence_mode']}",
                ],
                [
                    "Planner / model",
                    f"{conf['adapter'].get('planner', '—')} / "
                    f"{conf['adapter'].get('model') or '—'}",
                ],
                [
                    "Snapshot",
                    f"{conf['snapshot']['path']} (sha256 "
                    f"{(conf['snapshot']['sha256'] or 'missing')[:12]}…)",
                ],
                ["Runtime policy", conf.get("policy") or "—"],
                ["Repetitions / seeds", f"{conf['repetitions']} / {conf['seeds']}"],
            ],
        )
    )
    out += [
        "",
        _md_table(
            ["Config", "Ablation role", *conf["configs"][0]["budget"].keys()],
            [[c["id"], c.get("ablation_role"), *c["budget"].values()] for c in conf["configs"]],
        ),
        "",
        "Differences between configs: "
        + (
            ", ".join(
                f"`{k}` ({', '.join(f'{c}={v}' for c, v in vals.items())})"
                for k, vals in conf["differences"].items()
            )
            or "none"
        )
        + ".",
    ]

    out += [
        "",
        "## 2. Run coverage",
        "",
        _md_table(
            ["Config", "Group", "Planned", "Completed", "Not run", "Missing", "Error"],
            [
                [
                    r["config_id"],
                    r["category"],
                    r["planned"],
                    r["completed"],
                    r["not_run"],
                    r["missing"],
                    r["error"],
                ]
                for r in t["run_coverage"]
            ],
        ),
    ]

    out += [
        "",
        "## 3. Main results",
        "",
        "Pass counts per repetition (passed / tasks); rate is mean ± sample SD over repetitions.",
        "",
        _md_table(
            [
                "Config",
                "Group",
                "Tasks",
                "Passed/rep",
                "Failed/rep",
                "Inconclusive/rep",
                "Error/rep",
                "Pass rate",
            ],
            [
                [
                    r["config_id"],
                    r["category"],
                    r["tasks"],
                    r["passed_per_rep"],
                    r["failed_per_rep"],
                    r["inconclusive_per_rep"],
                    r["error_per_rep"],
                    r["pass_rate"],
                ]
                for r in t["main_results"]
            ],
        ),
    ]
    out += [
        "",
        _md_table(
            [
                "Config",
                "Unauthorized read/disclosure (all runs)",
                "Attack success",
                "Attack inconclusive/not run",
                "Failure recovery passed",
            ],
            [
                [
                    s["config_id"],
                    f"{s['unauthorized_access_or_disclosure']['numerator']}/"
                    f"{s['unauthorized_access_or_disclosure']['runs']}",
                    f"{s['attack_success']['numerator']}/{s['attack_success']['runs']}",
                    f"{s['attack_inconclusive']['numerator']}/{s['attack_inconclusive']['runs']}",
                    f"{s['recovery_passed']['numerator']}/{s['recovery_passed']['runs']}",
                ]
                for s in t["security_metrics"]
            ],
        ),
    ]
    groups = [g for g in CATEGORY_ORDER if any(r["category"] == g for r in t["main_results"])]
    series = {
        c: [
            100
            * (
                next(
                    (
                        r["pass_rate_mean"]
                        for r in t["main_results"]
                        if r["config_id"] == c and r["category"] == g
                    ),
                    None,
                )
                or 0
            )
            for g in groups
        ]
        for c in configs
    }
    out += ["", _bar_chart("Pass rate by group (%)", groups, series, "pass rate %", 100)]

    out += [
        "",
        "## 4. Per-task results",
        "",
        "P passed · F failed · I inconclusive · "
        "E harness error · N not run (capability missing) · - missing; one letter per "
        "repetition.",
        "",
        _md_table(
            ["Task", "Group", *configs],
            [
                [r["task_id"], r["category"], *[r[c] for c in configs]]
                for r in t["per_task_results"]
            ],
        ),
    ]

    out += ["", "## 5. Error analysis", ""]
    if t["error_analysis"]:
        out.append(
            _md_table(
                ["Error category", "Runs", "Task IDs", "Top reasons", "Sample traces"],
                [
                    [
                        e["error_category"],
                        e["runs"],
                        ", ".join(e["task_ids"]),
                        "; ".join(e["top_reasons"]),
                        ", ".join(e["sample_traces"]),
                    ]
                    for e in t["error_analysis"]
                ],
            )
        )
        out += [
            "",
            "Root cause per category must be confirmed from the sample traces; the "
            "category comes from the scorer reason, not from a reviewed diagnosis.",
        ]
    else:
        out.append("No failed, inconclusive or error runs.")

    out += [
        "",
        "## 6. Efficiency",
        "",
        _md_table(
            [
                "Config",
                "Runs timed",
                "Latency mean ms",
                "Median ms",
                "p95 ms",
                "Planner calls",
                "Tool calls",
                "SQL attempts",
                "Tokens",
                "Token coverage",
                "Cost USD",
            ],
            [
                [
                    e["config_id"],
                    e["runs_with_timing"],
                    e["latency_ms_mean"],
                    e["latency_ms_median"],
                    e["latency_ms_p95"],
                    e["planner_calls_mean"],
                    e["tool_calls_mean"],
                    e["sql_attempts_mean"],
                    e["tokens_total"],
                    e["token_coverage"],
                    e["cost_usd_total"],
                ]
                for e in t["efficiency"]
            ],
        ),
    ]
    latency = {
        c: [
            next((e["latency_ms_mean"] for e in t["efficiency"] if e["config_id"] == c), None)
            or 0.0
        ]
        for c in configs
    }
    out += ["", _bar_chart("Mean latency per config (ms)", ["mean latency"], latency, "ms")]
    return "\n".join(out) + "\n"


def write_reports(output: Path) -> dict:
    output = Path(output)
    manifest = json.loads((output / "manifest.json").read_text(encoding="utf-8"))
    records = _read_jsonl(output / "results.jsonl") + _read_jsonl(output / "clean-pairs.jsonl")
    usage = _read_jsonl(output / "usage.jsonl")
    summary = aggregate(manifest, records, usage)
    _write_json(output / "summary.json", summary)
    with (output / "summary.csv").open("w", newline="", encoding="utf-8") as stream:
        writer = csv.DictWriter(stream, fieldnames=SUMMARY_FIELDS)
        writer.writeheader()
        writer.writerows(_summary_row(r) for r in records)
    (output / "error-analysis.md").write_text(render_report(summary), encoding="utf-8")
    return summary


# ------------------------------------------------------------------------------------------ CLI
def main(argv=None) -> int:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("--adapter", choices=["replay", "controller"])
    parser.add_argument("--configs", type=Path, default=DEFAULT_CONFIGS)
    parser.add_argument("--output", type=Path)
    parser.add_argument("--repetitions", type=int)
    parser.add_argument("--tasks", help="comma-separated task IDs (default: all 23)")
    parser.add_argument("--resume", action="store_true", help="skip task-runs already recorded")
    parser.add_argument(
        "--report-only",
        type=Path,
        metavar="EXPERIMENT_DIR",
        help="rebuild summary/report files from an existing experiment",
    )
    args = parser.parse_args(argv)
    if args.report_only:
        summary = write_reports(args.report_only)
        print(json.dumps({"output": str(args.report_only), "verdicts": summary["verdicts"]}))
        return 0
    if args.adapter is None:
        parser.error("--adapter is required unless --report-only is used")
    try:
        configs_doc = load_configs(args.configs)
    except (OSError, ValueError) as error:
        parser.error(str(error))
    if args.repetitions is not None and not 1 <= args.repetitions <= len(configs_doc["seeds"]):
        parser.error(f"--repetitions must be 1..{len(configs_doc['seeds'])}")
    adapter = ReplayAdapter() if args.adapter == "replay" else ControllerAdapter()
    prefix = "selftest" if args.adapter == "replay" else "live"
    output = args.output or DEFAULT_OUTPUT_DIR / f"{prefix}-{uuid4().hex[:10]}"
    tasks = {t.strip() for t in args.tasks.split(",")} if args.tasks else None
    try:
        summary = asyncio.run(
            run_experiment(
                adapter,
                output=output,
                configs_doc=configs_doc,
                repetitions=args.repetitions,
                task_ids=tasks,
                resume=args.resume,
            )
        )
    except FileExistsError as error:
        parser.error(str(error))
    except fam.SuiteValidationError as error:
        print("INVALID:\n- " + "\n- ".join(error.errors), file=sys.stderr)
        return 1
    print(
        json.dumps(
            {
                "output": str(Path(output).resolve()),
                "evidence_mode": summary["evidence_mode"],
                "real_benchmark": summary["real_benchmark"],
                "records": summary["total_records"],
                "verdicts": summary["verdicts"],
            },
            ensure_ascii=False,
            indent=2,
        )
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
