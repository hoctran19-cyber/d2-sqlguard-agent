"""Static checks for the provisional Financial legitimate-task draft (suite financial-d2).

This module validates task *definitions* only. It never runs an agent, never connects to
PostgreSQL and is not accepted by ``evaluation.manifest`` / ``evaluation.runner`` (which stay
fixture-only for the sales bootstrap). The optional SQLite reference check opens a local
SQLite file read-only and compares it with the recorded reference artifact; SQLite results
are never certified as PostgreSQL expected rows.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import sqlite3
import sys
from pathlib import Path

import sqlglot
from sqlglot import exp
from sqlglot.optimizer.scope import traverse_scope

REPO_ROOT = Path(__file__).resolve().parent.parent
SUITE_DIR = Path(__file__).parent / "datasets" / "financial"
DEFAULT_MANIFEST = SUITE_DIR / "legitimate-tasks.v0.1.json"
DEFAULT_REFERENCE = SUITE_DIR / "sqlite-reference.v0.1.json"
POSTGRES_GOLD_SOURCE = REPO_ROOT / "financial-postgresql-gold-sql.json"
MINIDEV_ENV = "SQLGUARD_MINIDEV_DIR"

SCHEMA_VERSION = "financial-legitimate-draft-0.1"
SUITE_ID = "financial-d2"
# Legitimate task ID -> (role, BIRD Financial question_id).
SELECTION = {
    "D2-L01": ("operator", 89),
    "D2-L02": ("operator", 119),
    "D2-L03": ("operator", 173),
    "D2-L04": ("analyst", 93),
    "D2-L05": ("analyst", 128),
    "D2-L06": ("analyst", 168),
    "D2-L07": ("analyst", 186),
    "D2-L08": ("credit_officer", 98),
    "D2-L09": ("credit_officer", 99),
    "D2-L10": ("credit_officer", 136),
}
# Content hashes of the PostgreSQL Gold source (repo root) and the role-pool inputs
# ($SQLGUARD_MINIDEV_DIR); the manifest no longer carries a sources block.
POSTGRES_GOLD_SHA256 = "6dffd1fd01ec2820b97e6b28d556659057540f2f339e06cc61336f979f2bc6b4"
ROLE_POOL_SHA256 = {
    "operator": "7cbae0ce8cc46fa9cc0afeb036a33c2312410b6f75058bbc6754174a1690bd07",
    "analyst": "b9ccdbe47c576f27c2ad42adeb76f2a9637fbb3c42ea6a19542c3831f3921077",
    "credit_officer": "4aee952a013e42de56ad62299c1688541caccb5c6db2a88aa7509fc2915b35ff",
}
ROLE_POOL_FILES = {
    "operator": "financial-postgresql-legitimate.operator.vi.json",
    "analyst": "financial-postgresql-legitimate.analyst.vi.json",
    "credit_officer": "financial-postgresql-legitimate.credit-officer.vi.json",
}
PLANNED_COMPOSITION = {
    "legitimate": 10,
    "authorization": 3,
    "mixed": 2,
    "injection": 4,
    "failure": 2,
    "clean": 2,
}
COMPARISONS = {"unordered_rows", "tie_aware_ordered_rows", "single_row_any_of_tied_extreme"}
VALUE_KINDS = {"integer", "text", "float"}
# Individual keys analyst may use to JOIN/COUNT but never return or group-and-return.
INDIVIDUAL_KEYS = {"client_id", "account_id", "disp_id", "trans_id", "loan_id", "order_id"}
MODEL_INPUT_FIELDS = ("suite_id", "id", "role", "question", "evidence")


class SuiteValidationError(ValueError):
    """Raised with every detected problem, not only the first one."""

    def __init__(self, errors: list[str]) -> None:
        self.errors = errors
        super().__init__("; ".join(errors))


def sha256_bytes(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def sha256_text(text: str) -> str:
    return sha256_bytes(text.encode("utf-8"))


def sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with Path(path).open("rb") as handle:
        for chunk in iter(lambda: handle.read(1 << 20), b""):
            digest.update(chunk)
    return digest.hexdigest()


def load_json(path: Path):
    return json.loads(Path(path).read_text(encoding="utf-8"))


def sql_column_refs(sql: str, dialect: str = "postgres") -> set[tuple[str, str]]:
    """Return every (table, column) a SELECT reads, resolving aliases and derived tables."""
    tree = sqlglot.parse_one(sql, read=dialect)
    refs: set[tuple[str, str]] = set()
    for scope in traverse_scope(tree):
        tables = {
            name: source.name.lower()
            for name, source in scope.sources.items()
            if isinstance(source, exp.Table)
        }
        for column in scope.columns:
            qualifier = column.table
            if qualifier in tables:
                refs.add((tables[qualifier], column.name.lower()))
            elif qualifier and qualifier in scope.sources:
                continue  # Derived-table column; its inner scope is traversed separately.
            elif not qualifier and len(scope.sources) == 1 and tables:
                refs.add((next(iter(tables.values())), column.name.lower()))
            else:
                raise ValueError(f"Cannot resolve column {column.sql()} in: {sql}")
    return refs


def sql_projection_count(sql: str, dialect: str = "postgres") -> int:
    return len(sqlglot.parse_one(sql, read=dialect).selects)


def aggregate_only_violations(sql: str) -> list[str]:
    """Static analyst check: outputs must be aggregates or non-key GROUP BY dimensions."""
    tree = sqlglot.parse_one(sql, read="postgres")
    group = tree.args.get("group")
    grouped = {e.sql().lower() for e in group.expressions} if group else set()
    problems = []
    has_aggregate = False
    for projection in tree.selects:
        bare = [
            column
            for column in projection.find_all(exp.Column)
            if not column.find_ancestor(exp.AggFunc)
        ]
        has_aggregate |= projection.find(exp.AggFunc) is not None
        for column in bare:
            if column.name.lower() in INDIVIDUAL_KEYS:
                problems.append(f"returns individual key {column.sql()}")
            elif column.sql().lower() not in grouped:
                problems.append(f"non-aggregated column {column.sql()} not in GROUP BY")
    if not has_aggregate:
        problems.append("no aggregate output")
    if any(e.name.lower() in INDIVIDUAL_KEYS for e in (group.expressions if group else [])):
        # Grouping by a district key is fine; grouping by an individual key is not.
        problems.append("GROUP BY individual key")
    return problems


def public_inputs(document: dict) -> list[dict]:
    """Model-facing projection: no gold, expected rows, source SQL or reference results."""
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


def _check_suite(document: dict, errors: list[str]) -> None:
    if document.get("schema_version") != SCHEMA_VERSION:
        errors.append(f"schema_version must be {SCHEMA_VERSION}")
    suite = document.get("suite") or {}
    if suite.get("suite_id") != SUITE_ID:
        errors.append(f"suite_id must be {SUITE_ID}")
    if suite.get("status") != "draft" or suite.get("runnable") is not False:
        errors.append("suite must be status=draft and runnable=false")
    if suite.get("fixture_runner_compatible") is not False:
        errors.append("suite must declare fixture_runner_compatible=false")
    plan = document.get("run_plan") or {}
    if plan.get("status") != "planned_only":
        errors.append("run_plan.status must be planned_only")
    configs, reps = plan.get("configs") or [], plan.get("repetitions")
    if len(configs) != 2 or reps != 3:
        errors.append("run_plan must declare 2 configs x 3 repetitions")
    if plan.get("composition") != PLANNED_COMPOSITION:
        errors.append("run_plan.composition must be 10/3/2/4/2 + 2 clean")
    main = sum(v for k, v in PLANNED_COMPOSITION.items() if k != "clean")
    expected_runs = {"main": main * 2 * 3, "clean": 2 * 2 * 3}
    if plan.get("planned_runs") != expected_runs:
        errors.append(f"run_plan.planned_runs must be {expected_runs}")


def _check_task(task: dict, document: dict, gold_source: dict, root: Path, errors: list[str]):
    task_id = task.get("id")
    role, question_id = SELECTION[task_id]
    where = f"{task_id}:"
    if task.get("category") != "legitimate" or task.get("role") != role:
        errors.append(f"{where} must be legitimate/{role}")
    for field in ("question", "evidence", "comparison", "gold_sql"):
        if not isinstance(task.get(field), str) or not task[field].strip():
            errors.append(f"{where} missing {field}")
    source = task.get("source") or {}
    if source.get("question_id") != question_id or source.get("dialect") != "postgresql":
        errors.append(f"{where} source must be postgresql question_id {question_id}")
    record = gold_source.get(question_id)
    if record is None:
        errors.append(f"{where} question_id {question_id} absent from PostgreSQL gold source")
        return
    for key, source_key in (("question_en", "question"), ("evidence_en", "evidence")):
        if source.get(key) != record[source_key]:
            errors.append(f"{where} source.{key} differs from PostgreSQL source")
    if source.get("difficulty") != record["difficulty"] or source.get("db_id") != "financial":
        errors.append(f"{where} source difficulty/db_id differs")

    gold_path = (root / task.get("gold_sql", "")).resolve()
    if not gold_path.is_file() or root.resolve() not in gold_path.parents:
        errors.append(f"{where} gold_sql file missing or outside suite directory")
        return
    gold_text = gold_path.read_text(encoding="utf-8")
    if gold_text != record["SQL"] + "\n":
        errors.append(f"{where} gold SQL file is not the exact PostgreSQL source SQL")
    if task.get("gold_sql_sha256") != sha256_text(record["SQL"]):
        errors.append(f"{where} gold_sql_sha256 mismatch")

    expected = task.get("expected") or {}
    if (expected.get("status"), expected.get("disposition")) != ("succeeded", "full"):
        errors.append(f"{where} expected must be succeeded/full")
    if expected.get("omitted_fields") != []:
        errors.append(f"{where} expected.omitted_fields must be empty")
    if expected.get("rows") is not None or expected.get("row_count") is not None:
        if expected.get("validation_status") != "postgresql_validated":
            errors.append(f"{where} PostgreSQL rows present without postgresql_validated")
    elif expected.get("validation_status") != "pending_postgresql_validation":
        errors.append(f"{where} null rows require pending_postgresql_validation")

    columns = task.get("output_columns") or []
    width = sql_projection_count(record["SQL"])
    if len(columns) != width or len(expected.get("columns") or []) != width:
        errors.append(f"{where} output/expected column width != gold projection width {width}")
    if [c.get("position") for c in columns] != list(range(1, width + 1)):
        errors.append(f"{where} output_columns positions must be 1..{width}")
    if any(c.get("kind") not in VALUE_KINDS for c in columns):
        errors.append(f"{where} output column kind must be one of {sorted(VALUE_KINDS)}")
    if [c.get("name") for c in columns] != expected.get("columns"):
        errors.append(f"{where} expected.columns must match output_columns names")

    comparator = task.get("comparator") or {}
    if task.get("comparison") not in COMPARISONS or comparator.get("mode") != task.get(
        "comparison"
    ):
        errors.append(f"{where} comparison/comparator.mode invalid or inconsistent")
    if comparator.get("column_match") != "positional":
        errors.append(f"{where} comparator must match columns by position")
    for column in columns:
        if column.get("kind") == "float":
            tol = column.get("tolerance") or {}
            if not (isinstance(tol.get("abs"), float) and isinstance(tol.get("rel"), float)):
                errors.append(f"{where} float column needs explicit abs/rel tolerance")
        elif column.get("tolerance") is not None:
            errors.append(f"{where} non-float column must compare exactly")

    security = task.get("security") or {}
    if security.get("expected_forbidden_accesses") != []:
        errors.append(f"{where} legitimate task must expect no forbidden accesses")
    refs = sql_column_refs(record["SQL"])
    declared = {tuple(item.split(".", 1)) for item in security.get("referenced_columns", [])}
    if declared != refs:
        errors.append(f"{where} referenced_columns != columns parsed from gold SQL")
    allow = {
        (table, column.lower())
        for table, cols in document["policy"]["allowlists"][role].items()
        for column in cols
    }
    if refs - allow:
        errors.append(f"{where} gold SQL reads columns outside {role} allowlist: {refs - allow}")
    if role == "analyst":
        if security.get("aggregate_only") is not True:
            errors.append(f"{where} analyst task must declare aggregate_only=true")
        for problem in aggregate_only_violations(record["SQL"]):
            errors.append(f"{where} analyst aggregate-only: {problem}")

    for field in ("attack", "fault", "pair"):
        if field not in task or task[field] is not None:
            errors.append(f"{where} {field} must be present and null for legitimate tasks")
    run = task.get("run") or {}
    if run.get("status") != "draft" or not run.get("evidence_mode"):
        errors.append(f"{where} run must be explicit draft with evidence_mode")
    if run.get("budget_profile") not in (document.get("budget_profiles") or {}):
        errors.append(f"{where} unknown budget_profile")
    refinement = task.get("prompt_refinement") or {}
    if refinement.get("sql_changed") is not False:
        errors.append(f"{where} prompt_refinement must record sql_changed=false")
    if refinement.get("status") not in {"unchanged_from_role_pool", "refined"}:
        errors.append(f"{where} prompt_refinement.status invalid")


def validate_suite(document: dict, *, root: Path = SUITE_DIR, gold_source_path=None) -> dict:
    """Validate the draft suite statically; return it unchanged or raise SuiteValidationError."""
    errors: list[str] = []
    if not isinstance(document, dict):
        raise SuiteValidationError(["suite must be a JSON object"])
    _check_suite(document, errors)
    gold_source_path = Path(gold_source_path or POSTGRES_GOLD_SOURCE)
    if sha256_file(gold_source_path) != POSTGRES_GOLD_SHA256:
        errors.append("PostgreSQL gold source hash differs from POSTGRES_GOLD_SHA256")
    gold_source = {
        r["question_id"]: r for r in load_json(gold_source_path) if r["db_id"] == "financial"
    }
    tasks = document.get("tasks")
    if not isinstance(tasks, list):
        raise SuiteValidationError(errors + ["tasks must be a list"])
    ids = [t.get("id") for t in tasks]
    if sorted(ids) != sorted(SELECTION) or len(set(ids)) != len(ids):
        errors.append(f"tasks must be exactly the task IDs {sorted(SELECTION)}; got {ids}")
    pairs = [(t.get("role"), (t.get("source") or {}).get("question_id")) for t in tasks]
    if len(set(pairs)) != len(pairs):
        errors.append("duplicate (role, question_id) pair")
    for task in tasks:
        if task.get("id") in SELECTION:
            _check_task(task, document, gold_source, Path(root), errors)
    for item in public_inputs(document) if not errors else []:
        if set(item) != set(MODEL_INPUT_FIELDS):
            errors.append("public input projection leaked extra fields")
    if errors:
        raise SuiteValidationError(errors)
    return document


def load_suite(path=DEFAULT_MANIFEST) -> dict:
    path = Path(path)
    return validate_suite(load_json(path), root=path.parent)


def minidev_dir() -> Path:
    return Path(os.environ.get(MINIDEV_ENV) or REPO_ROOT.parent / "minidev")


def check_role_pool_sources(document: dict, minidev: Path) -> list[str]:
    """Compare recorded role-pool prompts/hashes with the local (read-only) minidev inputs."""
    errors = []
    pools = {}
    for role, name in ROLE_POOL_FILES.items():
        path = minidev / name
        if sha256_file(path) != ROLE_POOL_SHA256[role]:
            errors.append(f"role pool {name} hash differs from ROLE_POOL_SHA256")
        pools[role] = {r["question_id"]: r for r in load_json(path)}
    for task in document["tasks"]:
        pool = task["source"].get("role_pool") or {}
        record = pools[task["role"]].get(task["source"]["question_id"])
        if record is None:
            errors.append(f"{task['id']}: question absent from {task['role']} role pool")
            continue
        if pool.get("question_vi") != record["question"]:
            errors.append(f"{task['id']}: role_pool.question_vi differs from pool file")
        if pool.get("evidence_vi") != record["evidence"]:
            errors.append(f"{task['id']}: role_pool.evidence_vi differs from pool file")
        if record["SQL"] + "\n" != (SUITE_DIR / task["gold_sql"]).read_text(encoding="utf-8"):
            errors.append(f"{task['id']}: role pool SQL differs from gold file")
        unchanged = (task["question"], task["evidence"]) == (record["question"], record["evidence"])
        status = task["prompt_refinement"]["status"]
        if unchanged != (status == "unchanged_from_role_pool"):
            errors.append(f"{task['id']}: prompt_refinement.status inconsistent with pool text")
    return errors


def run_sqlite_reference(reference: dict, database: Path) -> dict[str, dict]:
    """Re-run the recorded SQLite queries read-only; return {task_id: {columns, rows}}."""
    uri = f"{Path(database).resolve().as_uri()}?mode=ro"
    connection = sqlite3.connect(uri, uri=True)
    try:
        results = {}
        for task_id, entry in reference["results"].items():
            cursor = connection.execute(entry["sqlite_sql"])
            results[task_id] = {
                "columns": [d[0] for d in cursor.description],
                "rows": [list(row) for row in cursor.fetchall()],
            }
            for name, check in (entry.get("diagnostics") or {}).items():
                rows = [list(row) for row in connection.execute(check["sql"]).fetchall()]
                results[task_id][f"diagnostic:{name}"] = rows
        return results
    finally:
        connection.close()


def check_sqlite_reference(reference: dict, document: dict, minidev: Path) -> list[str]:
    errors = []
    if reference.get("certifies_postgresql") is not False:
        errors.append("SQLite reference must declare certifies_postgresql=false")
    if set(reference["results"]) != {t["id"] for t in document["tasks"]}:
        errors.append("SQLite reference task IDs differ from suite tasks")
    source = minidev / reference["sqlite_gold_source"]["path"]
    if sha256_file(source) != reference["sqlite_gold_source"]["sha256"]:
        errors.append("SQLite gold source hash differs")
    sqlite_gold = {r["question_id"]: r for r in load_json(source) if r["db_id"] == "financial"}
    widths = {t["id"]: len(t["output_columns"]) for t in document["tasks"]}
    for task_id, entry in reference["results"].items():
        record = sqlite_gold[entry["question_id"]]
        if entry["sqlite_sql"] != record["SQL"] or entry["translated"] is not False:
            errors.append(f"{task_id}: SQLite SQL is not the verbatim SQLite source gold")
        if entry["sqlite_sql_sha256"] != sha256_text(entry["sqlite_sql"]):
            errors.append(f"{task_id}: sqlite_sql_sha256 mismatch")
        if len(entry["columns"]) != widths[task_id] or entry["row_count"] != len(entry["rows"]):
            errors.append(f"{task_id}: reference width/row_count inconsistent")
    for label, snapshot in reference["databases"].items():
        path = minidev / snapshot["path"]
        if sha256_file(path) != snapshot["sha256"]:
            errors.append(f"SQLite snapshot {label} hash differs; reference is stale")
            continue
        actual = run_sqlite_reference(reference, path)
        for task_id, entry in reference["results"].items():
            got = actual[task_id]
            if got["columns"] != entry["columns"] or got["rows"] != entry["rows"]:
                errors.append(f"{task_id}: recorded SQLite rows differ on snapshot {label}")
            for name, check in (entry.get("diagnostics") or {}).items():
                if got[f"diagnostic:{name}"] != check["rows"]:
                    errors.append(f"{task_id}: diagnostic {name} differs on snapshot {label}")
    return errors


def main(argv=None) -> int:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("--manifest", type=Path, default=DEFAULT_MANIFEST)
    parser.add_argument("--reference", type=Path, default=DEFAULT_REFERENCE)
    parser.add_argument(
        "--with-local-sources",
        action="store_true",
        help=f"Also check minidev role pools and re-run SQLite reference (${MINIDEV_ENV}).",
    )
    parser.add_argument("--print-public-inputs", action="store_true")
    args = parser.parse_args(argv)
    try:
        document = load_suite(args.manifest)
    except SuiteValidationError as error:
        print("INVALID:\n- " + "\n- ".join(error.errors), file=sys.stderr)
        return 1
    print(f"static checks passed: {len(document['tasks'])} legitimate tasks, suite {SUITE_ID}")
    if args.with_local_sources:
        root = minidev_dir()
        errors = check_role_pool_sources(document, root)
        errors += check_sqlite_reference(load_json(args.reference), document, root)
        if errors:
            print("INVALID:\n- " + "\n- ".join(errors), file=sys.stderr)
            return 1
        print(f"local source + read-only SQLite reference checks passed ({root})")
    if args.print_public_inputs:
        print(json.dumps(public_inputs(document), ensure_ascii=False, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
