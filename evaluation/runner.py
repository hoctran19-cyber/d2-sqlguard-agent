"""Run provisional fixture cases: python -m evaluation.runner --help."""

import argparse
import asyncio
import csv
import hashlib
import json
import subprocess
from collections import Counter
from datetime import UTC, datetime
from pathlib import Path
from time import perf_counter
from uuid import uuid4

from evaluation.fixture_adapter import FIXTURE_SQL, run_fixture
from evaluation.manifest import DEFAULT_MANIFEST, load_manifest
from evaluation.scorer import score


def write_json(path, value):
    path.write_text(json.dumps(value, ensure_ascii=False, indent=2, default=str), encoding="utf-8")


def git_metadata():
    root = Path(__file__).resolve().parents[1]
    try:
        commit = subprocess.check_output(
            ["git", "rev-parse", "HEAD"], cwd=root, text=True, stderr=subprocess.DEVNULL
        ).strip()
        dirty = bool(
            subprocess.check_output(
                ["git", "status", "--porcelain"], cwd=root, text=True, stderr=subprocess.DEVNULL
            ).strip()
        )
        return {"commit": commit, "dirty": dirty}
    except (OSError, subprocess.CalledProcessError):
        return {"commit": None, "dirty": None}


def implementation_hash():
    root = Path(__file__).resolve().parents[1]
    digest = hashlib.sha256()
    paths = sorted((root / "src" / "sqlguard").rglob("*.py"))
    paths += sorted((root / "evaluation").glob("*.py"))
    for path in paths:
        digest.update(str(path.relative_to(root)).encode())
        digest.update(path.read_bytes())
    return digest.hexdigest()


async def run_suite(document, output, *, repetitions=1, max_sql_attempts=3, on_record=None):
    """on_record(record), if given, is called after each task-run is persisted (UI progress)."""
    if repetitions < 1 or max_sql_attempts not in (1, 3):
        raise ValueError("repetitions >= 1 and max_sql_attempts in {1, 3} required")
    output = Path(output)
    output.mkdir(parents=True, exist_ok=False)  # Never overwrite an existing experiment.
    (output / "traces").mkdir()
    fixture_hash = hashlib.sha256(FIXTURE_SQL.read_bytes()).hexdigest()
    write_json(
        output / "manifest.json",
        {
            "mode": "fixture_only",
            "real_benchmark": False,
            "created_at": datetime.now(UTC).isoformat(),
            **git_metadata(),
            "implementation_sha256": implementation_hash(),
            "fixture_sha256": fixture_hash,
            "manifest": document,
            "repetitions": repetitions,
            "max_sql_attempts": max_sql_attempts,
            "latency_scope": "fixture setup/controller/normalization/cleanup; excludes scoring",
            "limitations": [
                "no LLM",
                "SQLite fixture, not PostgreSQL",
                "no SQL repair",
                "scripted policy, not production authorization",
            ],
        },
    )
    records = []
    with (
        (output / "results.jsonl").open("x", encoding="utf-8") as results_file,
        (output / "usage.jsonl").open("x", encoding="utf-8") as usage_file,
    ):
        for repetition in range(1, repetitions + 1):
            for index, case in enumerate(document["tasks"], start=1):
                started = perf_counter()
                try:
                    actual = await run_fixture(case, max_sql_attempts=max_sql_attempts)
                    latency_ms = (perf_counter() - started) * 1000
                    trace = actual.pop("trace")
                    verdict = score(case, actual)
                except Exception as error:
                    # Harness failures are not model failures or passing results.
                    latency_ms = (perf_counter() - started) * 1000
                    actual = {"status": "harness_error", "error_type": type(error).__name__}
                    trace = []
                    verdict = {
                        "verdict": "error",
                        "passed": None,
                        "utility_passed": None,
                        "failure_reasons": ["evaluation_infrastructure"],
                        "unknown_reasons": [],
                        "evidence_scope": "fixture_only",
                    }
                trace_ref = f"traces/r{repetition}-case{index}.json"
                write_json(output / trace_ref, trace)
                record = {
                    "task_id": case["id"],
                    "category": case["category"],
                    "repetition": repetition,
                    "mode": "fixture_only",
                    "config_id": f"fixture-attempts-{max_sql_attempts}",
                    "latency_ms": latency_ms,
                    "actual": actual,
                    "trace_ref": trace_ref,
                    **verdict,
                }
                records.append(record)
                results_file.write(json.dumps(record, ensure_ascii=False, default=str) + "\n")
                results_file.flush()
                usage_file.write(
                    json.dumps(
                        {
                            "task_id": case["id"],
                            "repetition": repetition,
                            "run_id": actual.get("run_id"),
                            "usage": actual.get("usage"),
                        }
                    )
                    + "\n"
                )
                usage_file.flush()
                if on_record is not None:
                    on_record(record)

    fields = ["task_id", "repetition", "config_id", "verdict", "latency_ms", "mode"]
    with (output / "summary.csv").open("x", newline="", encoding="utf-8") as stream:
        writer = csv.DictWriter(stream, fieldnames=fields, extrasaction="ignore")
        writer.writeheader()
        writer.writerows(records)
    counts = Counter(record["verdict"] for record in records)
    summary = {
        "mode": "fixture_only",
        "total": len(records),
        "counts": {label: counts[label] for label in ("passed", "failed", "inconclusive", "error")},
        "real_benchmark": False,
        "note": "Fixture checks only; no LLM accuracy, reflection or injection-defense claims.",
    }
    write_json(output / "summary.json", summary)
    return summary


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--manifest", type=Path, default=DEFAULT_MANIFEST)
    parser.add_argument("--output", type=Path)
    parser.add_argument("--repetitions", type=int, default=1)
    parser.add_argument("--max-sql-attempts", type=int, choices=[1, 3], default=3)
    args = parser.parse_args()
    if args.repetitions < 1:
        parser.error("--repetitions must be >= 1")
    try:
        document = load_manifest(args.manifest)
    except (ValueError, OSError) as error:
        parser.error(str(error))
    output = args.output or (
        Path(__file__).parent / "reports" / "generated" / f"bootstrap-{uuid4().hex[:12]}"
    )
    if output.exists():
        parser.error("Output already exists; choose a new directory")
    summary = asyncio.run(
        run_suite(
            document,
            output,
            repetitions=args.repetitions,
            max_sql_attempts=args.max_sql_attempts,
        )
    )
    print(json.dumps({"output": str(output.resolve()), **summary}, ensure_ascii=False, indent=2))
    # Inconclusive I03 is expected in fixture mode, not silently counted as passed.
    return 1 if summary["counts"]["failed"] or summary["counts"]["error"] else 0


if __name__ == "__main__":
    raise SystemExit(main())
