"""Financial failure tasks D2-F01/D2-F02 (financial-d2, SQLite) and whole-suite composition.

Validates ``failure-tasks.v0.1.json`` statically: each task reuses a legitimate base question,
declares a harness-side fault (never part of the model input) and an expected controlled
outcome. It never injects a fault, never opens a database and never runs an agent; fault hooks,
budgets and the terminal error mapping are pending the runtime contract. ``check_composition``
counts every component manifest against the planned 21 main + 2 clean tasks.
"""

from __future__ import annotations

import argparse
import json
import re
import sys
from collections import Counter
from pathlib import Path

import sqlglot

from evaluation.financial_auth_mixed import (
    LEAK_MARKERS,
    LEGITIMATE_MANIFEST,
    SQLITE_REFERENCE,
    SUITE_ID,
    SuiteValidationError,
    allowlists_sha256,
    gold_safety_problems,
    non_operational_metadata,
    role_allow,
)
from evaluation.financial_legitimate import (
    PLANNED_COMPOSITION,
    SUITE_DIR,
    aggregate_only_violations,
    load_json,
    sha256_file,
    sha256_text,
    sql_column_refs,
)

DEFAULT_MANIFEST = SUITE_DIR / "failure-tasks.v0.1.json"
SCHEMA_VERSION = "financial-failure-draft-0.1"
ORACLE_REF = "sqlite-reference.v0.1.json"
COMPONENT_MANIFESTS = (
    "legitimate-tasks.v0.1.json",
    "auth-tasks.v0.1.json",
    "mixed-tasks.v0.1.json",
    "injection-tasks.v0.1.json",
    "failure-tasks.v0.1.json",
    "clean-tasks.v0.1.json",
)
TASKS = {
    "D2-F01": {
        "role": "analyst",
        "base": "D2-L04",
        "fault": "sql_column_mutation",
        "stage": "pre_gate",
        "comparison": "unordered_rows",
    },
    "D2-F02": {
        "role": "operator",
        "base": "D2-L01",
        "fault": "db_unavailable",
        "stage": "post_gate_pre_execution",
        "comparison": "behavior_only",
    },
}
F01_REPAIR_CONFIGS = {"repair_enabled", "repair_disabled"}
MODEL_INPUT_FIELDS = ("suite_id", "id", "role", "question", "evidence")
READINESS = {
    "definition": "definitions_validated",
    "oracle": "oracle_validated",
    "runtime": "runtime_pending",
}


def public_inputs(document: dict) -> list[dict]:
    """Model-facing fields only: the fault, gold and expected outcome are never included."""
    suite_id = document["suite"]["suite_id"]
    return [
        {
            "suite_id": suite_id,
            "id": task["id"],
            "role": task["role"],
            "question": task["question"],
            "evidence": task["evidence"],
        }
        for task in document["tasks"]
    ]


def contains_number(text: str, value: str) -> bool:
    """True if ``value`` appears as a standalone number (``13`` or ``13.`` but not ``13.5``)."""
    return re.search(rf"(?<![\w.]){re.escape(value)}(?!\w|\.\d)", text) is not None


def _gold_text(task: dict) -> str:
    return (SUITE_DIR / task["gold_sql"]).read_text(encoding="utf-8").rstrip("\n")


def _check_header(document: dict, legitimate: dict, errors: list[str]) -> None:
    if document.get("schema_version") != SCHEMA_VERSION:
        errors.append(f"schema_version must be {SCHEMA_VERSION}")
    suite = document.get("suite") or {}
    if (suite.get("suite_id"), suite.get("component"), suite.get("engine")) != (
        SUITE_ID,
        "failure",
        "sqlite",
    ):
        errors.append(f"suite must be {SUITE_ID}/failure on engine sqlite")
    if suite.get("status") != "draft" or suite.get("runnable") is not False:
        errors.append("suite must be status=draft and runnable=false")
    if suite.get("runtime_adapter") is not None or suite.get("fixture_runner_compatible"):
        errors.append("suite must declare runtime_adapter=null and fixture_runner_compatible=false")
    policy = document.get("policy") or {}
    if policy.get("allowlists_sha256") != allowlists_sha256(legitimate["policy"]["allowlists"]):
        errors.append("policy.allowlists_sha256 differs from the role allowlists")
    if (document.get("oracle_artifact") or {}).get("path") != ORACLE_REF:
        errors.append(f"oracle_artifact.path must be {ORACLE_REF}")
    if document.get("missing_evidence") != "inconclusive (never safe/0)":
        errors.append("missing evidence must be declared inconclusive")
    profiles = document.get("budget_profiles") or {}
    if any(p.get("status") != "pending_A_contract" for p in profiles.values()) or not profiles:
        errors.append("budget profiles must stay pending_A_contract")
    errors += [f"non-operational metadata: {item}" for item in non_operational_metadata(document)]
    blob = json.dumps(document, ensure_ascii=False)
    errors += [f"forbidden value marker {m!r} present" for m in LEAK_MARKERS.values() if m in blob]


def _check_common(task: dict, spec: dict, base: dict, ref: dict, allow: set, errors) -> bool:
    """Shared checks; returns False when the gold file is missing (later checks need it)."""
    where = task["id"]
    if (task.get("category"), task.get("role")) != ("failure", spec["role"]):
        errors.append(f"{where}: category/role must be failure/{spec['role']}")
    source = task.get("source") or {}
    if source.get("base_task") != spec["base"] or source.get("question_id") != ref["question_id"]:
        errors.append(f"{where}: source must be base task {spec['base']} / {ref['question_id']}")
    if (task.get("question"), task.get("evidence")) != (base["question"], base["evidence"]):
        errors.append(f"{where}: question/evidence must equal base task {spec['base']}")
    if task.get("comparison") != spec["comparison"]:
        errors.append(f"{where}: comparison must be {spec['comparison']}")
    if task.get("attack") is not None or task.get("pair") is not None:
        errors.append(f"{where}: attack and pair must be null")
    if task.get("readiness") != READINESS:
        errors.append(f"{where}: readiness must be {READINESS}")
    run = task.get("run") or {}
    if run.get("status") != "draft" or run.get("budget_profile") != "draft-default":
        errors.append(f"{where}: run must be draft with budget_profile draft-default")
    security = task.get("security") or {}
    if security.get("role_binding") != "session_fixed" or security.get("forbidden_resources"):
        errors.append(f"{where}: role must be session_fixed with no forbidden resources")

    # Gold is the verbatim SQLite SQL of the base task; it is evaluator-only.
    path = SUITE_DIR / str(task.get("gold_sql"))
    if task.get("gold_dialect") != "sqlite" or not path.name.endswith(".sqlite.sql"):
        errors.append(f"{where}: gold must be gold_dialect=sqlite in a .sqlite.sql file")
    if not path.is_file():
        errors.append(f"{where}: SQLite gold file missing")
        return False
    gold = _gold_text(task)
    if sha256_file(path) != task.get("gold_sql_sha256"):
        errors.append(f"{where}: gold_sql_sha256 mismatch")
    if sha256_text(gold) != ref["sqlite_sql_sha256"]:
        errors.append(f"{where}: gold must equal the SQLite source SQL of {spec['base']}")
    errors += [f"{where}: {p}" for p in gold_safety_problems(gold, allow, [])]
    columns = task.get("output_columns") or []
    width = len(sqlglot.parse_one(gold, read="sqlite").selects)
    if [c.get("name") for c in columns] != [c["name"] for c in base["output_columns"]]:
        errors.append(f"{where}: output_columns must match base task {spec['base']}")
    if [c.get("position") for c in columns] != list(range(1, width + 1)):
        errors.append(f"{where}: output_columns positions must be 1..{width}")

    fault = task.get("fault") or {}
    if (fault.get("kind"), fault.get("stage")) != (spec["fault"], spec["stage"]):
        errors.append(f"{where}: fault must be {spec['fault']} at stage {spec['stage']}")
    # The fault is harness setup: its kind must never leak into the model-facing text.
    if spec["fault"] in (task.get("question") or "") + (task.get("evidence") or ""):
        errors.append(f"{where}: fault details must not appear in question/evidence")
    return True


def _check_f01(task: dict, ref: dict, allowlists: dict, errors: list[str]) -> None:
    where = task["id"]
    fault, expected = task.get("fault") or {}, task.get("expected") or {}
    if fault.get("ordinal") != 1:
        errors.append(f"{where}: column mutation applies only to the first proposed SQL")
    rule = fault.get("rule") or {}
    target = tuple(str(rule.get("target_column", "")).lower().split(".", 1))
    gold_refs = sql_column_refs(_gold_text(task), dialect="sqlite")
    if target not in gold_refs:
        errors.append(f"{where}: mutation target must be a column the base query needs")
    replacement = str(rule.get("replacement_column", "")).lower()
    known = {c.lower() for role in allowlists.values() for cols in role.values() for c in cols}
    if not replacement or replacement in known:
        errors.append(f"{where}: replacement column must not exist in the schema")
    if "never" not in str(fault.get("feedback_to_planner", "")).lower():
        errors.append(f"{where}: feedback must exclude Gold SQL and the correct column")
    if not fault.get("if_not_applicable"):
        errors.append(f"{where}: an untriggered fault needs an explicit not-applicable rule")
    if (task.get("security") or {}).get("aggregate_only") is not True:
        errors.append(f"{where}: analyst task must declare aggregate_only=true")
    errors += [
        f"{where}: analyst aggregate-only: {p}"
        for p in aggregate_only_violations(_gold_text(task), "sqlite")
    ]
    by_config = expected.get("by_config") or {}
    if set(by_config) != F01_REPAIR_CONFIGS or not expected.get("config_mapping"):
        errors.append(f"{where}: expected needs {sorted(F01_REPAIR_CONFIGS)} + config_mapping")
        return
    repaired, plain = by_config["repair_enabled"], by_config["repair_disabled"]
    if (repaired.get("status"), repaired.get("disposition")) != ("succeeded", "full"):
        errors.append(f"{where}: repair_enabled must expect succeeded/full")
    if repaired.get("rows_ref") != f"{ORACLE_REF}#/results/D2-L04/rows" or ref["row_count"] < 1:
        errors.append(f"{where}: repair_enabled rows must come from the base baseline")
    if repaired.get("columns") != [c["name"] for c in task.get("output_columns") or []]:
        errors.append(f"{where}: repair_enabled columns must match output_columns")
    if (plain.get("status"), plain.get("disposition"), plain.get("rows")) != (
        "failed",
        "error",
        [],
    ):
        errors.append(f"{where}: repair_disabled must expect failed/error with no rows")


def _check_f02(task: dict, ref: dict, errors: list[str]) -> None:
    where = task["id"]
    fault, expected = task.get("fault") or {}, task.get("expected") or {}
    if fault.get("ordinal") != "all" or fault.get("real_execution") is not False:
        errors.append(f"{where}: db_unavailable must apply to every attempt without real execution")
    if fault.get("retryable") is not True:
        errors.append(f"{where}: db_unavailable must be declared retryable")
    shape = (expected.get("status"), expected.get("disposition"), expected.get("rows"))
    if shape != ("failed", "error", []) or expected.get("columns") != []:
        errors.append(f"{where}: expected must be failed/error with no columns or rows")
    if expected.get("error_code") != "db_unavailable":
        errors.append(f"{where}: expected error_code must be db_unavailable")
    if expected.get("result_equality") != "not_scored":
        errors.append(f"{where}: result equality must not be scored for an expected failure")
    if expected.get("forbidden_answer_values_ref") != f"{ORACLE_REF}#/results/D2-L01/rows":
        errors.append(f"{where}: baseline values must be referenced as forbidden answer values")
    # The healthy-baseline answer is referenced, never embedded in the task definition.
    blob = json.dumps({k: v for k, v in task.items() if k != "gold_sql_sha256"}, ensure_ascii=False)
    for value in (str(cell) for row in ref["rows"] for cell in row if cell is not None):
        if contains_number(blob, value):
            errors.append(f"{where}: baseline answer value {value} must not be embedded")


def validate_manifest(document: dict, *, legitimate: dict, reference: dict) -> dict:
    errors: list[str] = []
    if not isinstance(document, dict):
        raise SuiteValidationError(["manifest must be a JSON object"])
    _check_header(document, legitimate, errors)
    tasks = document.get("tasks") or []
    if [t.get("id") for t in tasks] != list(TASKS):
        raise SuiteValidationError(errors + [f"task ids must be exactly {list(TASKS)}"])
    allowlists = legitimate["policy"]["allowlists"]
    legit = {t["id"]: t for t in legitimate["tasks"]}
    for task in tasks:
        spec = TASKS[task["id"]]
        ref = reference["results"][spec["base"]]
        allow = role_allow(allowlists, spec["role"])
        if not _check_common(task, spec, legit[spec["base"]], ref, allow, errors):
            continue
        if task["id"] == "D2-F01":
            _check_f01(task, ref, allowlists, errors)
        else:
            _check_f02(task, ref, errors)
    if errors:
        raise SuiteValidationError(errors)
    return document


def check_composition(root: Path = SUITE_DIR) -> list[str]:
    """Count task categories over every component manifest against the planned suite size."""
    counts: Counter = Counter()
    ids: list[str] = []
    for name in COMPONENT_MANIFESTS:
        path = Path(root) / name
        if not path.is_file():
            return [f"component manifest missing: {name}"]
        document = load_json(path)
        if (document.get("suite") or {}).get("suite_id") != SUITE_ID:
            return [f"{name}: suite_id must be {SUITE_ID}"]
        for task in document.get("tasks") or []:
            counts[task.get("category")] += 1
            ids.append(task.get("id"))
    errors = []
    if dict(counts) != PLANNED_COMPOSITION:
        errors.append(f"composition {dict(counts)} != planned {PLANNED_COMPOSITION}")
    duplicates = sorted(i for i, n in Counter(ids).items() if n > 1)
    if duplicates:
        errors.append(f"duplicate task ids across components: {duplicates}")
    return errors


def load_suite(path=DEFAULT_MANIFEST) -> dict:
    return validate_manifest(
        load_json(path),
        legitimate=load_json(LEGITIMATE_MANIFEST),
        reference=load_json(SQLITE_REFERENCE),
    )


def main(argv=None) -> int:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("--manifest", type=Path, default=DEFAULT_MANIFEST)
    parser.add_argument("--print-public-inputs", action="store_true")
    args = parser.parse_args(argv)
    try:
        document = load_suite(args.manifest)
    except SuiteValidationError as error:
        print("INVALID:\n- " + "\n- ".join(error.errors), file=sys.stderr)
        return 1
    errors = check_composition(args.manifest.parent)
    if errors:
        print("INVALID:\n- " + "\n- ".join(errors), file=sys.stderr)
        return 1
    main_total = sum(v for k, v in PLANNED_COMPOSITION.items() if k != "clean")
    print(f"definitions_validated: {len(document['tasks'])} failure tasks")
    print(f"composition: {main_total} main + {PLANNED_COMPOSITION['clean']} clean tasks")
    print("runtime_pending: no fault hooks or runtime adapter; not a benchmark result")
    if args.print_public_inputs:
        print(json.dumps(public_inputs(document), ensure_ascii=False, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
