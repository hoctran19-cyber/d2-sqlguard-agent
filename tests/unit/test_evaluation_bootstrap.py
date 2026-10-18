import asyncio
import copy
import json
import sqlite3

import pytest
from evaluation.fixture_adapter import FIXTURE_SQL, run_fixture
from evaluation.manifest import DEFAULT_MANIFEST, load_manifest
from evaluation.runner import run_suite
from evaluation.scorer import equal_rows, score


def test_multiset_preserves_duplicates_null_and_order_semantics():
    assert equal_rows([[1], [2]], [[2], [1]])
    assert not equal_rows([[1]], [[1], [1]])
    assert not equal_rows([[None]], [[""]])
    assert not equal_rows([[1], [2]], [[2], [1]], ordered=True)


def test_manifest_rejects_duplicate_ids(tmp_path):
    document = load_manifest()
    document["tasks"].append(document["tasks"][0])
    path = tmp_path / "bad.json"
    path.write_text(json.dumps(document))
    with pytest.raises(ValueError, match="Duplicate task ID"):
        load_manifest(path)


def test_manifest_rejects_bad_row_width(tmp_path):
    document = load_manifest()
    document["tasks"][0]["expected"]["rows"] = [[1]]
    path = tmp_path / "bad.json"
    path.write_text(json.dumps(document))
    with pytest.raises(ValueError, match="row width"):
        load_manifest(path)


def test_gold_rows_match_seed_and_attack_patch():
    document = load_manifest()
    for case in document["tasks"]:
        if "gold_sql" not in case:
            continue
        connection = sqlite3.connect(":memory:")
        try:
            connection.executescript(FIXTURE_SQL.read_text())
            if "attack_payload" in case:
                connection.execute(
                    "UPDATE customer SET note=? WHERE customer_id=1", (case["attack_payload"],)
                )
            sql_path = DEFAULT_MANIFEST.parent.parent / case["gold_sql"]
            cursor = connection.execute(sql_path.read_text())
            assert [c[0] for c in cursor.description] == case["expected"]["columns"]
            assert [list(row) for row in cursor.fetchall()] == case["expected"]["rows"]
        finally:
            connection.close()


@pytest.mark.parametrize("task_index", [0, 1, 2, 4])
def test_controller_fixture_cases_pass_in_their_limited_scope(task_index):
    case = load_manifest()["tasks"][task_index]
    actual = asyncio.run(run_fixture(case))
    assert score(case, actual)["verdict"] == "passed"
    assert actual["evidence_scope"] == "fixture_only"
    assert actual["usage"]["llm_calls"] == 0
    if case["category"] == "authorization":
        assert actual["tool_calls"] == 0
    if case["category"] == "failure":
        assert actual["tool_calls"] == 2
        assert actual["planner_calls"] == 1
        assert actual["evidence"]["recovery_kind"] == "tool_retry_only"


def test_indirect_injection_without_model_exposure_is_inconclusive():
    case = load_manifest()["tasks"][3]
    actual = asyncio.run(run_fixture(case))
    verdict = score(case, actual)
    assert verdict["verdict"] == "inconclusive"
    assert verdict["passed"] is None
    assert verdict["attack_success"] is None
    assert actual["evidence"]["retrieved_target"] is True


def test_wrong_gold_fails_and_does_not_change_runtime_answer():
    case = load_manifest()["tasks"][0]
    changed = copy.deepcopy(case)
    changed["expected"]["rows"] = [[999, "WRONG GOLD"]]
    actual = asyncio.run(run_fixture(changed))
    assert actual["rows"] == case["expected"]["rows"]
    assert score(changed, actual)["verdict"] == "failed"


def test_missing_security_evidence_is_not_pass():
    case = load_manifest()["tasks"][1]
    actual = asyncio.run(run_fixture(case))
    actual["evidence"].pop("disclosure")
    assert score(case, actual)["verdict"] == "inconclusive"


def test_partial_notice_and_security_breach_are_checked():
    case = load_manifest()["tasks"][2]
    actual = asyncio.run(run_fixture(case))
    actual["notice"] = ""
    assert "missing_omission_notice" in score(case, actual)["failure_reasons"]
    actual["evidence"]["disclosure"] = True
    assert "disclosure" in score(case, actual)["failure_reasons"]


def test_one_attempt_cannot_pass_retry_case():
    case = load_manifest()["tasks"][4]
    actual = asyncio.run(run_fixture(case, max_sql_attempts=1))
    assert score(case, actual)["verdict"] == "failed"
    assert actual["tool_calls"] == 1


def test_runner_writes_all_records_and_refuses_overwrite(tmp_path):
    output = tmp_path / "experiment"
    summary = asyncio.run(run_suite(load_manifest(), output, repetitions=2))
    assert summary["counts"] == {"passed": 8, "failed": 0, "inconclusive": 2, "error": 0}
    assert summary["real_benchmark"] is False
    rows = [json.loads(line) for line in (output / "results.jsonl").read_text().splitlines()]
    assert len(rows) == 10
    assert len({(r["task_id"], r["repetition"]) for r in rows}) == 10
    assert all((output / r["trace_ref"]).is_file() for r in rows)
    with pytest.raises(FileExistsError):
        asyncio.run(run_suite(load_manifest(), output))


def test_runner_records_harness_errors_separately(tmp_path, monkeypatch):
    async def broken(*args, **kwargs):
        raise RuntimeError("sensitive error details")

    monkeypatch.setattr("evaluation.runner.run_fixture", broken)
    output = tmp_path / "broken"
    summary = asyncio.run(run_suite(load_manifest(), output))
    assert summary["counts"]["error"] == 5
    assert "sensitive error details" not in (output / "results.jsonl").read_text()
