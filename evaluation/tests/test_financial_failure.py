"""Static checks for the Financial failure tasks and whole-suite composition (financial-d2).

Run explicitly: ``pytest -q evaluation/tests`` (the default ``pytest`` testpath is ``tests/``).
"""

import copy
import json
import shutil

import pytest

from evaluation import financial_failure as ff
from evaluation.financial_auth_mixed import LEGITIMATE_MANIFEST, SQLITE_REFERENCE
from evaluation.financial_legitimate import PLANNED_COMPOSITION, load_json


@pytest.fixture(scope="module")
def sources():
    return load_json(LEGITIMATE_MANIFEST), load_json(SQLITE_REFERENCE)


@pytest.fixture
def document():
    return load_json(ff.DEFAULT_MANIFEST)


def _task(document, task_id):
    return next(t for t in document["tasks"] if t["id"] == task_id)


def _errors(document, sources):
    legitimate, reference = sources
    with pytest.raises(ff.SuiteValidationError) as error:
        ff.validate_manifest(document, legitimate=legitimate, reference=reference)
    return " | ".join(error.value.errors)


def test_manifest_passes_static_validation(document, sources):
    legitimate, reference = sources
    assert ff.validate_manifest(document, legitimate=legitimate, reference=reference) is document
    assert [(t["id"], t["role"], t["category"]) for t in document["tasks"]] == [
        ("D2-F01", "analyst", "failure"),
        ("D2-F02", "operator", "failure"),
    ]


def test_tasks_reuse_base_question_and_sqlite_gold(document, sources):
    legitimate, reference = sources
    legit = {t["id"]: t for t in legitimate["tasks"]}
    for task in document["tasks"]:
        base = ff.TASKS[task["id"]]["base"]
        assert (task["question"], task["evidence"]) == (
            legit[base]["question"],
            legit[base]["evidence"],
        )
        gold = (ff.SUITE_DIR / task["gold_sql"]).read_text(encoding="utf-8")
        assert gold == reference["results"][base]["sqlite_sql"] + "\n"


def test_public_inputs_exclude_fault_gold_and_expected(document):
    inputs = ff.public_inputs(document)
    assert [set(item) for item in inputs] == [set(ff.MODEL_INPUT_FIELDS)] * 2
    blob = json.dumps(inputs, ensure_ascii=False)
    for word in ("SELECT", "average_salary_not_a_column", "db_unavailable", "pre_gate", "rows_ref"):
        assert word not in blob


def test_f01_expects_recovery_or_controlled_stop(document):
    expected = _task(document, "D2-F01")["expected"]["by_config"]
    assert (expected["repair_enabled"]["status"], expected["repair_enabled"]["disposition"]) == (
        "succeeded",
        "full",
    )
    assert expected["repair_disabled"]["rows"] == []


def test_f02_expects_failure_without_answer(document, sources):
    task = _task(document, "D2-F02")
    assert (task["expected"]["status"], task["expected"]["rows"]) == ("failed", [])
    baseline = sources[1]["results"]["D2-L01"]["rows"]
    assert baseline and task["expected"]["result_equality"] == "not_scored"


@pytest.mark.parametrize(
    ("mutate", "message"),
    [
        (lambda d: d["tasks"].pop(), "task ids must be exactly"),
        (lambda d: _task(d, "D2-F01").update(role="operator"), "failure/analyst"),
        (lambda d: _task(d, "D2-F02").update(question="khác"), "base task D2-L01"),
        (lambda d: _task(d, "D2-F01").update(gold_sql_sha256="0" * 64), "sha256 mismatch"),
        (lambda d: _task(d, "D2-F01").update(gold_sql="gold/D2-F02.sqlite.sql"), "SQLite source"),
        (lambda d: _task(d, "D2-F02").update(gold_sql="gold/missing.sqlite.sql"), "file missing"),
        (lambda d: _task(d, "D2-F01").update(attack={"payload": "x"}), "attack and pair"),
        (lambda d: _task(d, "D2-F01")["fault"].update(stage="post_gate"), "fault must be"),
        (lambda d: _task(d, "D2-F01")["fault"].update(ordinal=2), "first proposed SQL"),
        (
            lambda d: _task(d, "D2-F01")["fault"]["rule"].update(replacement_column="a2"),
            "must not exist",
        ),
        (
            lambda d: _task(d, "D2-F01")["fault"]["rule"].update(target_column="client.address"),
            "base query needs",
        ),
        (
            lambda d: _task(d, "D2-F01")["expected"]["by_config"].pop("repair_disabled"),
            "config_mapping",
        ),
        (lambda d: _task(d, "D2-F02")["fault"].update(real_execution=True), "every attempt"),
        (lambda d: _task(d, "D2-F02")["expected"].update(rows=[[13]]), "no columns or rows"),
        (lambda d: _task(d, "D2-F02").update(oracle="Expected count 13."), "must not be embedded"),
        (
            lambda d: _task(d, "D2-F02")["expected"].update(result_equality="unordered_rows"),
            "not be scored",
        ),
        (
            lambda d: _task(d, "D2-F02").update(
                question=_task(d, "D2-F02")["question"] + " db_unavailable"
            ),
            "question/evidence",
        ),
        (lambda d: d["policy"].update(allowlists_sha256="0" * 64), "allowlists_sha256"),
        (lambda d: d["suite"].update(runnable=True), "runnable=false"),
        (lambda d: d["budget_profiles"]["draft-default"].update(status="final"), "pending_A"),
        (lambda d: _task(d, "D2-F01")["readiness"].update(runtime="ready"), "readiness"),
        (lambda d: d.update(selection_note="picked"), "non-operational metadata"),
        (lambda d: _task(d, "D2-F01").update(oracle="selected for the demo"), "non-operational"),
    ],
)
def test_validator_rejects_mutations(document, sources, mutate, message):
    mutated = copy.deepcopy(document)
    mutate(mutated)
    assert message in _errors(mutated, sources)


def test_composition_is_21_main_plus_2_clean():
    assert ff.check_composition() == []
    main = sum(v for k, v in PLANNED_COMPOSITION.items() if k != "clean")
    assert (main, PLANNED_COMPOSITION["clean"], PLANNED_COMPOSITION["failure"]) == (21, 2, 2)


def test_composition_detects_missing_failure_component(tmp_path):
    for name in ff.COMPONENT_MANIFESTS:
        shutil.copy(ff.SUITE_DIR / name, tmp_path / name)
    assert ff.check_composition(tmp_path) == []
    document = load_json(tmp_path / "failure-tasks.v0.1.json")
    document["tasks"] = document["tasks"][:1]
    (tmp_path / "failure-tasks.v0.1.json").write_text(json.dumps(document), encoding="utf-8")
    assert "composition" in " ".join(ff.check_composition(tmp_path))
    (tmp_path / "failure-tasks.v0.1.json").unlink()
    assert ff.check_composition(tmp_path) == ["component manifest missing: failure-tasks.v0.1.json"]


def test_cli_reports_definitions_and_composition(capsys):
    assert ff.main([]) == 0
    out = capsys.readouterr().out
    assert "2 failure tasks" in out and "21 main + 2 clean" in out and "runtime_pending" in out
