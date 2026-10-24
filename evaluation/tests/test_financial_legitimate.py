"""Static checks for the draft Financial legitimate suite (financial-d2).

Run explicitly: ``pytest -q evaluation/tests`` (the default ``pytest`` testpath is ``tests/``).
"""

import copy
import json

import pytest

from evaluation import financial_legitimate as fl
from evaluation.manifest import validate_manifest


@pytest.fixture(scope="module")
def suite():
    return fl.load_json(fl.DEFAULT_MANIFEST)


def _errors(document):
    with pytest.raises(fl.SuiteValidationError) as error:
        fl.validate_suite(document)
    return " | ".join(error.value.errors)


def _task(document, task_id):
    return next(t for t in document["tasks"] if t["id"] == task_id)


def test_suite_passes_static_validation(suite):
    assert fl.validate_suite(suite) is suite
    assert {t["id"]: (t["role"], t["source"]["question_id"]) for t in suite["tasks"]} == (
        fl.SELECTION
    )


def test_gold_files_are_exact_sqlite_source_sql(suite):
    reference = fl.load_json(fl.DEFAULT_REFERENCE)["results"]
    for task in suite["tasks"]:
        entry = reference[task["id"]]
        assert task["gold_dialect"] == "sqlite"
        assert task["gold_sql"] == f"gold/{task['id']}.sqlite.sql"
        assert entry["question_id"] == task["source"]["question_id"]
        text = (fl.SUITE_DIR / task["gold_sql"]).read_text(encoding="utf-8")
        assert text == entry["sqlite_sql"] + "\n"
        assert task["gold_sql_sha256"] == fl.sha256_text(entry["sqlite_sql"])


def test_expected_rows_stay_pending_until_postgresql_validation(suite):
    for task in suite["tasks"]:
        assert task["expected"]["rows"] is None
        assert task["expected"]["validation_status"] == "pending_postgresql_validation"
    document = copy.deepcopy(suite)
    _task(document, "D2-L01")["expected"]["rows"] = [[13]]
    assert "without postgresql_validated" in _errors(document)


def test_not_accepted_by_fixture_manifest(suite):
    with pytest.raises(ValueError, match="fixture_only"):
        validate_manifest(suite)


def test_public_inputs_exclude_gold_expected_and_sources(suite):
    inputs = fl.public_inputs(suite)
    assert len(inputs) == 10
    blob = json.dumps(inputs, ensure_ascii=False)
    for item in inputs:
        assert set(item) == set(fl.MODEL_INPUT_FIELDS)
    for task in suite["tasks"]:
        sql = (fl.SUITE_DIR / task["gold_sql"]).read_text(encoding="utf-8").strip()
        assert sql not in blob
    assert "SELECT" not in blob and "sqlite_reference" not in blob


@pytest.mark.parametrize(
    ("mutate", "message"),
    [
        (lambda d: d["tasks"].pop(), "exactly the task IDs"),
        (lambda d: d["tasks"].append(copy.deepcopy(d["tasks"][0])), "exactly the task IDs"),
        (lambda d: _task(d, "D2-L04").update(role="operator"), "legitimate/analyst"),
        (lambda d: _task(d, "D2-L02").update(gold_sql="gold/D2-L01.sqlite.sql"), "exact SQLite"),
        (lambda d: _task(d, "D2-L02").update(gold_dialect="postgresql"), "gold_dialect=sqlite"),
        (lambda d: _task(d, "D2-L03").update(gold_sql="../../manifest.py"), "outside suite"),
        (lambda d: _task(d, "D2-L06")["output_columns"].pop(), "column width"),
        (lambda d: _task(d, "D2-L06")["output_columns"][0].update(tolerance=None), "tolerance"),
        (lambda d: _task(d, "D2-L08").update(attack={"payload": "x"}), "attack must be"),
        (lambda d: _task(d, "D2-L09").pop("pair"), "pair must be"),
        (lambda d: _task(d, "D2-L10")["security"]["referenced_columns"].pop(), "parsed from"),
        (
            lambda d: _task(d, "D2-L10")["security"].update(
                expected_forbidden_accesses=["client.id_number"]
            ),
            "no forbidden",
        ),
        (lambda d: d["policy"]["allowlists"]["operator"].pop("order"), "outside operator"),
        (lambda d: d["suite"].update(runnable=True), "runnable=false"),
        (lambda d: d["run_plan"].update(repetitions=5), "2 configs x 3"),
        (
            lambda d: d["run_plan"]["composition"].update(authorization=2),
            "composition must be 10/3/2/4/2",
        ),
        (
            lambda d: d["run_plan"].update(planned_runs={"main": 120, "clean": 12}),
            "planned_runs must be {'main': 126, 'clean': 12}",
        ),
        (lambda d: _task(d, "D2-L05").update(comparison="ordered_rows"), "comparison"),
    ],
)
def test_validator_rejects_mutations(suite, mutate, message):
    document = copy.deepcopy(suite)
    mutate(document)
    assert message in _errors(document)


def test_column_refs_resolve_aliases_and_derived_tables():
    sql = (fl.SUITE_DIR / "gold" / "D2-L03.sqlite.sql").read_text(encoding="utf-8")
    assert fl.sql_column_refs(sql, "sqlite") == {
        ("account", "account_id"),
        ("account", "frequency"),
        ("order", "account_id"),
        ("order", "amount"),
        ("order", "k_symbol"),
    }


def test_analyst_aggregate_only_check():
    for task_id in ("D2-L04", "D2-L05", "D2-L06", "D2-L07"):
        sql = (fl.SUITE_DIR / "gold" / f"{task_id}.sqlite.sql").read_text(encoding="utf-8")
        assert fl.aggregate_only_violations(sql, "sqlite") == []
    leak = "SELECT T1.client_id, COUNT(*) FROM client AS T1 GROUP BY T1.client_id"
    assert "returns individual key T1.client_id" in fl.aggregate_only_violations(leak)
    assert "no aggregate output" in fl.aggregate_only_violations("SELECT gender FROM client")


def test_sqlite_reference_is_marked_non_postgresql(suite):
    reference = fl.load_json(fl.DEFAULT_REFERENCE)
    assert reference["certifies_postgresql"] is False
    for task in suite["tasks"]:
        entry = reference["results"][task["id"]]
        assert entry["translated"] is False
        assert len(entry["columns"]) == len(task["output_columns"])
        assert entry["row_count"] == len(entry["rows"])


@pytest.mark.skipif(
    not (fl.minidev_dir() / "MINIDEV" / "mini_dev_sqlite.json").is_file(),
    reason=f"local minidev inputs not found (set {fl.MINIDEV_ENV})",
)
def test_local_sources_and_sqlite_reference(suite):
    assert fl.check_role_pool_sources(suite, fl.minidev_dir()) == []
    reference = fl.load_json(fl.DEFAULT_REFERENCE)
    assert fl.check_sqlite_reference(reference, suite, fl.minidev_dir()) == []
