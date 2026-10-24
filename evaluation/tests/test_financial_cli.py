"""Smoke tests for ``python -m evaluation.runner validate|run|score|summarize`` (offline).

Run explicitly: ``pytest -q evaluation/tests`` (the default ``pytest`` testpath is ``tests/``).
The replay adapter is a harness self-test; no model or network is used here.
"""

import json

import pytest
import yaml

from evaluation import financial_cli as cli
from evaluation import runner

SMOKE = ["D2-L01", "D2-A01", "D2-M01", "D2-I01"]


def _experiment(tmp_path, **changes):
    document = yaml.safe_load(cli.DEFAULT_EXPERIMENT.read_text(encoding="utf-8"))
    document["runtime"]["planner"] = "demo"  # No Ollama probe in unit tests.
    for dotted, value in changes.items():
        target = document
        *parents, leaf = dotted.split(".")
        for key in parents:
            target = target[key]
        target[leaf] = value
    path = tmp_path / "experiment.yaml"
    path.write_text(yaml.safe_dump(document, sort_keys=False), encoding="utf-8")
    return path


def _statuses(checks):
    return {name: status for name, status, _ in checks}


def _smoke(tmp_path, output="smoke-001"):
    path = _experiment(tmp_path)
    code = runner.main(
        [
            "run",
            "--experiment",
            str(path),
            "--adapter",
            "replay",
            "--tasks",
            *SMOKE,
            "--repetitions",
            "1",
            "--output",
            str(tmp_path / output),
        ]
    )
    return code, tmp_path / output


def test_shipped_experiment_file_is_valid():
    experiment = cli.load_experiment(cli.DEFAULT_EXPERIMENT)
    assert [c["id"] for c in experiment["configs"]] == ["d2-agent", "d2-no-reflection"]
    assert experiment["smoke"]["tasks"] == SMOKE


def test_malformed_experiment_is_rejected(tmp_path):
    path = _experiment(tmp_path, repetitions=0)
    with pytest.raises(ValueError, match="repetitions"):
        cli.load_experiment(path)
    assert runner.main(["validate", "--experiment", str(path)]) == 2


def test_validate_replay_has_no_blocker(tmp_path):
    checks = cli.validate(cli.load_experiment(_experiment(tmp_path)), adapter_override="replay")
    statuses = _statuses(checks)
    assert "fail" not in statuses.values()
    assert statuses["definitions"] == statuses["snapshot"] == statuses["configs"] == "ok"
    assert statuses["adapter"] == "warn"  # Self-test is flagged as not a benchmark.


def test_validate_blocks_on_snapshot_and_runtime_policy(tmp_path):
    # bird_financial_v1 defines teller/credit/risk, none of the suite's task roles.
    changes = {"snapshot.sha256": "0" * 64, "runtime.policy": "bird_financial_v1"}
    experiment = cli.load_experiment(_experiment(tmp_path, **changes))
    statuses = _statuses(cli.validate(experiment))
    assert statuses["snapshot"] == "fail"
    assert statuses["runtime_policy"] == "fail"  # Task roles absent from the runtime policy.
    assert statuses["capabilities"] == "warn"
    unknown = _statuses(cli.validate(experiment, adapter_override="replay", tasks=["D2-X99"]))
    assert unknown["tasks"] == "fail"


def test_default_runtime_policy_defines_every_task_role(tmp_path):
    experiment = cli.load_experiment(_experiment(tmp_path))
    assert _statuses(cli.validate(experiment))["runtime_policy"] == "ok"


def test_blocked_run_writes_nothing(tmp_path):
    path = _experiment(tmp_path, **{"runtime.policy": "bird_financial_v1"})
    output = tmp_path / "blocked"
    assert (
        runner.main(
            ["run", "--experiment", str(path), "--tasks", "D2-L01", "--output", str(output)]
        )
        == 1
    )
    assert not output.exists()


def test_smoke_run_passes_health_check(tmp_path, capsys):
    code, output = _smoke(tmp_path)
    assert code == 0
    records = [json.loads(x) for x in (output / "results.jsonl").read_text().splitlines()]
    assert sorted({r["task_id"] for r in records}) == sorted(SMOKE)
    assert len(records) == len(SMOKE) * 2
    statuses = _statuses(cli.health_check(output))
    assert {
        statuses[k]
        for k in ("coverage", "record_shape", "traces", "harness_errors", "result_contract")
    } == {"ok"}
    manifest = json.loads((output / "manifest.json").read_text())
    assert manifest["experiment_file"]["path"] == "experiment.yaml"
    assert "coverage" in capsys.readouterr().out
    assert _smoke(tmp_path)[0] == 2  # Existing output is never overwritten.


def test_health_check_fails_on_missing_trace_and_harness_error(tmp_path):
    _, output = _smoke(tmp_path)
    records = (output / "results.jsonl").read_text().splitlines()
    first = json.loads(records[0])
    (output / first["trace_ref"]).unlink()
    broken = dict(json.loads(records[1]), verdict="error")
    (output / "results.jsonl").write_text(
        "\n".join([records[0], json.dumps(broken), *records[2:]]) + "\n"
    )
    statuses = _statuses(cli.health_check(output))
    assert statuses["traces"] == statuses["harness_errors"] == "fail"


def test_score_rescores_from_artifacts_without_runtime(tmp_path):
    _, output = _smoke(tmp_path)
    assert runner.main(["score", "--input", str(output)]) == 0
    manifest = json.loads((output / "manifest.json").read_text())
    assert manifest["scoring_history"][-1]["changed"] == 0
    record = next(
        json.loads(x)
        for x in (output / "results.jsonl").read_text().splitlines()
        if x and json.loads(x)["task_id"] == "D2-L01"
    )
    trace_path = output / record["trace_ref"]
    trace = json.loads(trace_path.read_text())
    trace["result"]["rows"] = [[0]]
    trace_path.write_text(json.dumps(trace))
    assert cli.rescore(output) == {"rescored": len(SMOKE) * 2, "changed": 1}
    rescored = next(
        json.loads(x)
        for x in (output / "results.jsonl").read_text().splitlines()
        if json.loads(x)["run_id"] == record["run_id"]
    )
    assert rescored["verdict"] == "failed" and "rows_mismatch" in rescored["failure_reasons"]
    assert rescored["run"] == record["run"]  # Runner metadata survives re-scoring.


def test_summarize_rebuilds_reports(tmp_path):
    _, output = _smoke(tmp_path)
    for name in ("summary.json", "summary.csv", "error-analysis.md"):
        (output / name).unlink()
    assert runner.main(["summarize", "--input", str(output)]) == 0
    for name in ("summary.json", "summary.csv", "error-analysis.md"):
        assert (output / name).is_file()
    assert runner.main(["summarize", "--input", str(tmp_path / "missing")]) == 2


def test_legacy_bootstrap_command_still_runs(tmp_path):
    assert runner.main(["bootstrap", "--output", str(tmp_path / "legacy")]) == 0
    assert (tmp_path / "legacy" / "summary.json").is_file()
