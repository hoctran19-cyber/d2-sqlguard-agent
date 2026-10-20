"""Audit local BIRD Mini-Dev data without running Gold SQL or an agent."""

from __future__ import annotations

import argparse
import hashlib
import json
import re
import sys
from collections import Counter
from datetime import UTC, date, datetime
from pathlib import Path
from typing import Any

OFFICIAL_DATASET_URL = "https://huggingface.co/datasets/birdsql/bird_mini_dev"
OFFICIAL_REPOSITORY_URL = "https://github.com/bird-bench/mini_dev"
SUPPORTED_DIALECTS = {"sqlite", "postgresql", "mysql"}
_DIALECT_ALIASES = {
    "pg": "postgresql",
    "postgres": "postgresql",
    "postgresql": "postgresql",
    "sqlite": "sqlite",
    "sqlite3": "sqlite",
    "mysql": "mysql",
}
_METADATA_FILENAMES = {"dataset_info.json", "state.json", "metadata.json"}
_COMMIT_SHA_PATTERN = re.compile(r"[0-9a-fA-F]{40}")
_SQL_FEATURES = {
    "case": re.compile(r"\bCASE\b", re.IGNORECASE),
    "exists": re.compile(r"\bEXISTS\b", re.IGNORECASE),
    "group_by": re.compile(r"\bGROUP\s+BY\b", re.IGNORECASE),
    "having": re.compile(r"\bHAVING\b", re.IGNORECASE),
    "join": re.compile(r"\bJOIN\b", re.IGNORECASE),
    "order_by": re.compile(r"\bORDER\s+BY\b", re.IGNORECASE),
    "subquery": re.compile(r"\(\s*SELECT\b", re.IGNORECASE),
    "union": re.compile(r"\bUNION\b", re.IGNORECASE),
    "window": re.compile(r"\bOVER\s*\(", re.IGNORECASE),
}


class DatasetAuditError(ValueError):
    """An actionable error in the selected local dataset input or its metadata."""


def audit_dataset(
    dataset_path: str | Path,
    *,
    dialect: str,
    revision: str,
    acquired_on: date,
    financial_db_id: str = "financial",
    target_count: int = 20,
) -> dict[str, Any]:
    """Return a deterministic audit and provisional candidate shortlist.

    Dataset content is read locally only. Candidate selection is a reproducible heuristic;
    every candidate remains pending human question/Gold SQL review and execution.
    """
    if not isinstance(revision, str) or _COMMIT_SHA_PATTERN.fullmatch(revision) is None:
        raise DatasetAuditError(
            "Dataset revision must be a full 40-character hexadecimal commit SHA."
        )
    if not isinstance(acquired_on, date) or isinstance(acquired_on, datetime):
        raise DatasetAuditError(
            "Acquisition date is required; pass the date the local data was obtained."
        )
    if not financial_db_id.strip():
        raise DatasetAuditError("Financial database ID must not be empty.")
    if target_count < 1:
        raise DatasetAuditError("Target candidate count must be at least 1.")

    paths = _resolve_dataset_files(Path(dataset_path), dialect)
    records: list[tuple[Path, int, dict[str, Any]]] = []
    for source_path in paths:
        records.extend((source_path, index, record) for index, record in _read_records(source_path))

    dialect_fallback = _normalize_dialect(dialect)
    dialect_counts: Counter[str] = Counter()
    ids: dict[str, dict[str, Any]] = {}
    missing_id_records: list[dict[str, Any]] = []
    missing_question_records: list[dict[str, Any]] = []
    missing_gold_records: list[dict[str, Any]] = []
    missing_db_records: list[dict[str, Any]] = []
    database_ids: set[str] = set()
    financial_rows: list[dict[str, Any]] = []

    for source_path, index, record in records:
        record_id = _first_value(record, ("question_id", "id"))
        source_ref = {"file": source_path.name, "record_index": index}
        if not _is_valid_source_id(record_id):
            missing_id_records.append(source_ref)
            stable_id = None
        else:
            stable_id = _stable_id(record_id)
            ids.setdefault(stable_id, {"id": record_id, "records": []})["records"].append(
                source_ref
            )

        db_id = record.get("db_id")
        if not isinstance(db_id, str) or not db_id.strip():
            missing_db_records.append(source_ref)
            db_id_text = None
        else:
            db_id_text = str(db_id)
            database_ids.add(db_id_text)

        question = record.get("question")
        question_missing = not isinstance(question, str) or not question.strip()
        if question_missing:
            missing_question_records.append(source_ref)

        gold_sql = record.get("SQL")
        gold_missing = not isinstance(gold_sql, str) or not gold_sql.strip()
        if gold_missing:
            missing_gold_records.append(source_ref)

        record_dialect = _first_value(record, ("sql_dialect", "dialect"))
        if _is_missing(record_dialect):
            resolved_dialect = dialect_fallback
        else:
            resolved_dialect = _normalize_dialect(str(record_dialect))
        dialect_counts[resolved_dialect] += 1

        if (
            db_id_text is None
            or db_id_text.strip().casefold() != financial_db_id.strip().casefold()
        ):
            continue
        financial_rows.append(
            {
                "source": source_ref,
                "case_id": record_id if stable_id is not None else None,
                "question": question if isinstance(question, str) else None,
                "db_id": db_id_text,
                "gold_sql": gold_sql if isinstance(gold_sql, str) else None,
                "dialect": resolved_dialect,
                "difficulty": record.get("difficulty"),
                "missing_question": question_missing,
                "missing_gold_sql": gold_missing,
            }
        )

    duplicate_ids = [
        {"id": values["id"], "records": values["records"]}
        for _, values in sorted(ids.items())
        if len(values["records"]) > 1
    ]
    duplicated_id_set = {
        stable_id for stable_id, values in ids.items() if len(values["records"]) > 1
    }
    supported_financial = [
        row
        for row in financial_rows
        if row["case_id"] is not None
        and _stable_id(row["case_id"]) not in duplicated_id_set
        and not row["missing_question"]
        and not row["missing_gold_sql"]
        and row["dialect"] in SUPPORTED_DIALECTS
    ]
    selected = (
        _select_candidates(supported_financial, target_count, revision)
        if len(supported_financial) >= target_count
        else []
    )
    candidate_pool = (
        _select_candidates(supported_financial, len(supported_financial), revision)
        if not selected
        else []
    )

    source_files = [
        {
            "file": path.name,
            "sha256": hashlib.sha256(path.read_bytes()).hexdigest(),
            "size_bytes": path.stat().st_size,
        }
        for path in paths
    ]
    unresolved = []
    if len(supported_financial) < target_count:
        unresolved.append(
            f"Only {len(supported_financial)} valid Financial records are available; "
            f"{target_count} are required for the requested shortlist."
        )
    if any(row["dialect"] not in SUPPORTED_DIALECTS for row in financial_rows):
        unresolved.append("Some Financial records use an unsupported SQL dialect.")
    if missing_id_records or duplicate_ids:
        unresolved.append("Missing or duplicate source IDs require manual resolution.")
    if missing_question_records or missing_gold_records:
        unresolved.append("Some source records are missing a question or Gold SQL.")

    return {
        "schema_version": 1,
        "report_type": "bird_dataset_audit_not_execution_accuracy",
        "audited_at_utc": datetime.now(UTC).isoformat(),
        "acquisition_date": acquired_on.isoformat(),
        "source": {
            "dataset_url": OFFICIAL_DATASET_URL,
            "repository_url": OFFICIAL_REPOSITORY_URL,
            "revision": revision,
            "files": source_files,
        },
        "summary": {
            "total_records": len(records),
            "financial_db_id": financial_db_id,
            "financial_record_count": len(financial_rows),
            "valid_financial_candidate_count": len(supported_financial),
            "missing_id_count": len(missing_id_records),
            "missing_id_records": missing_id_records,
            "duplicate_id_count": len(duplicate_ids),
            "duplicate_ids": duplicate_ids,
            "missing_question_count": len(missing_question_records),
            "missing_question_records": missing_question_records,
            "missing_gold_sql_count": len(missing_gold_records),
            "missing_gold_sql_records": missing_gold_records,
            "missing_db_id_count": len(missing_db_records),
            "missing_db_id_records": missing_db_records,
            "database_ids": sorted(database_ids, key=str.casefold),
            "unsupported_sql_dialects": [
                {"dialect": value, "record_count": count}
                for value, count in sorted(dialect_counts.items())
                if value not in SUPPORTED_DIALECTS
            ],
        },
        "financial_records": financial_rows,
        "candidate_report": {
            "target_count": target_count,
            "selected_count": len(selected),
            "status": "provisional_pending_human_review",
            "selection_method": (
                "Deterministic greedy coverage of available difficulty labels and SQL feature "
                "tokens; ties are resolved by stable source ID. This is not manual verification."
            ),
            "shortlist": selected,
            "candidate_pool": candidate_pool,
            "blockers": unresolved
            + [
                "Questions and Gold SQL still require human review against the selected benchmark "
                "revision and database schema.",
                "Gold SQL has not been executed or validated.",
            ],
        },
        "accuracy_claim": False,
    }


def _resolve_dataset_files(path: Path, dialect: str) -> list[Path]:
    requested_dialect = _normalize_dialect(dialect)
    if not path.exists():
        raise DatasetAuditError(
            f"Dataset path does not exist: {path}. Provide a local BIRD JSON/JSONL file or "
            "a directory containing one dialect's data files."
        )
    if path.is_file():
        if path.suffix.lower() not in {".json", ".jsonl"}:
            raise DatasetAuditError("Dataset file must have a .json or .jsonl extension.")
        _ensure_filename_dialect(path, requested_dialect)
        return [path]
    if not path.is_dir():
        raise DatasetAuditError(f"Dataset path is not a regular file or directory: {path}")

    files = sorted(
        candidate
        for candidate in path.rglob("*")
        if candidate.is_file()
        and candidate.suffix.lower() in {".json", ".jsonl"}
        and candidate.name.casefold() not in _METADATA_FILENAMES
    )
    if not files:
        raise DatasetAuditError(
            f"No dataset .json/.jsonl files found under {path}; download/export the dataset "
            "locally first, then pass its data file or containing directory."
        )
    identified = {candidate: _filename_dialect(candidate) for candidate in files}
    matched = [
        candidate
        for candidate, candidate_dialect in identified.items()
        if candidate_dialect == requested_dialect
    ]
    if matched:
        return matched

    if len(files) == 1:
        _ensure_filename_dialect(files[0], requested_dialect)
        return files

    identified_dialects = sorted({value for value in identified.values() if value is not None})
    if len(identified_dialects) == len(set(identified.values())) and identified_dialects:
        raise DatasetAuditError(
            f"Dataset files identify dialect(s) {', '.join(identified_dialects)}, which do not "
            f"match --dialect {requested_dialect!r}. Pass a matching file or correct --dialect."
        )
    raise DatasetAuditError(
        f"Found {len(files)} JSON data files under {path} and none identifies dialect "
        f"{requested_dialect!r}. Pass the exact intended file; if its name is ambiguous, "
        "the explicit --dialect value will be used as the caller's assertion."
    )


def _ensure_filename_dialect(path: Path, requested_dialect: str) -> None:
    identified = _filename_dialect(path)
    if identified is not None and identified != requested_dialect:
        raise DatasetAuditError(
            f"Dataset filename {path.name!r} identifies dialect {identified!r}, but "
            f"--dialect is {requested_dialect!r}. Pass the matching dialect or a file whose "
            "name does not identify a conflicting dialect."
        )


def _filename_dialect(path: Path) -> str | None:
    """Infer a dialect only from a complete filename token, not an arbitrary substring."""
    tokens = set(re.findall(r"[a-z0-9]+", path.stem.casefold()))
    matches = set()
    if tokens & {"sqlite", "sqlite3"}:
        matches.add("sqlite")
    if tokens & {"postgres", "postgresql", "pg"}:
        matches.add("postgresql")
    if "mysql" in tokens:
        matches.add("mysql")
    if len(matches) > 1:
        raise DatasetAuditError(
            f"Dataset filename {path.name!r} contains conflicting dialect markers: "
            f"{', '.join(sorted(matches))}. Rename/select the intended file explicitly."
        )
    return next(iter(matches), None)


def _read_records(path: Path) -> list[tuple[int, dict[str, Any]]]:
    try:
        text = path.read_text(encoding="utf-8")
    except (OSError, UnicodeError) as error:
        raise DatasetAuditError(f"Cannot read dataset file {path}: {error}") from None
    try:
        if path.suffix.lower() == ".jsonl":
            raw_records = [json.loads(line) for line in text.splitlines() if line.strip()]
        else:
            document = json.loads(text)
            if isinstance(document, list):
                raw_records = document
            elif isinstance(document, dict):
                wrapped = next(
                    (
                        document[key]
                        for key in ("records", "data")
                        if isinstance(document.get(key), list)
                    ),
                    None,
                )
                raw_records = wrapped if wrapped is not None else [document]
            else:
                raise DatasetAuditError("Dataset JSON root must be an array or an object.")
    except (json.JSONDecodeError, UnicodeDecodeError) as error:
        raise DatasetAuditError(
            f"Dataset file {path} is not valid UTF-8 JSON/JSONL: {error}"
        ) from None

    output = []
    for index, record in enumerate(raw_records):
        if not isinstance(record, dict):
            raise DatasetAuditError(
                f"Record {index} in {path.name} is not a JSON object; expected upstream "
                "question metadata fields such as question_id, db_id, question, and SQL."
            )
        output.append((index, record))
    if not output:
        raise DatasetAuditError(f"Dataset file {path} contains no records.")
    return output


def _select_candidates(
    records: list[dict[str, Any]], count: int, revision: str
) -> list[dict[str, Any]]:
    remaining = sorted(records, key=lambda row: _stable_sort_key(row["case_id"]))
    selected = []
    covered: set[str] = set()
    while remaining and len(selected) < count:
        scored = []
        for row in remaining:
            features = _candidate_features(row)
            scored.append(
                (len(features - covered), _stable_sort_key(row["case_id"]), row, features)
            )
        _, _, chosen, features = min(scored, key=lambda item: (-item[0], item[1]))
        added = sorted(features - covered)
        rationale = (
            "Adds coverage for " + ", ".join(added)
            if added
            else "Stable-ID fallback after available complexity/SQL features were covered"
        )
        selected.append(
            {
                "case_id": chosen["case_id"],
                "question": chosen["question"],
                "db_id": chosen["db_id"],
                "gold_sql_reference": {
                    "source_file": chosen["source"]["file"],
                    "source_record_id": chosen["case_id"],
                    "field": "SQL",
                    "dataset_revision": revision,
                },
                "source": chosen["source"],
                "dialect": chosen["dialect"],
                "difficulty": chosen["difficulty"],
                "selection_rationale": rationale,
                "verification_status": "pending",
                "gold_sql_execution_status": "not_executed",
            }
        )
        covered.update(features)
        remaining.remove(chosen)
    return selected


def _candidate_features(row: dict[str, Any]) -> set[str]:
    features = set()
    if isinstance(row["difficulty"], str) and row["difficulty"].strip():
        features.add(f"difficulty:{row['difficulty'].strip().casefold()}")
    query = row["gold_sql"] or ""
    feature_names = [name for name, pattern in _SQL_FEATURES.items() if pattern.search(query)]
    features.update(f"sql:{name}" for name in feature_names)
    size_band = "short" if len(query) <= 180 else "medium" if len(query) <= 500 else "long"
    features.add(f"sql_length:{size_band}")
    return features


def _first_value(record: dict[str, Any], names: tuple[str, ...]) -> Any:
    for name in names:
        if name in record:
            return record[name]
    return None


def _stable_id(value: Any) -> str:
    return (
        f"{type(value).__name__}:"
        f"{json.dumps(value, ensure_ascii=False, sort_keys=True, separators=(',', ':'))}"
    )


def _stable_sort_key(value: Any) -> str:
    return _stable_id(value).casefold()


def _is_valid_source_id(value: Any) -> bool:
    return (isinstance(value, str) and bool(value.strip())) or (
        isinstance(value, int) and not isinstance(value, bool)
    )


def _is_missing(value: Any) -> bool:
    return value is None or (isinstance(value, str) and not value.strip())


def _normalize_dialect(dialect: str) -> str:
    value = dialect.strip().casefold()
    return _DIALECT_ALIASES.get(value, value or "(missing)")


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("dataset_path", type=Path, help="Local BIRD JSON/JSONL file or directory")
    parser.add_argument(
        "--dialect",
        required=True,
        help="Dataset dialect/config name (for example sqlite, postgresql, or mysql)",
    )
    parser.add_argument(
        "--revision",
        required=True,
        help="Pinned upstream revision (full Hugging Face commit SHA recommended)",
    )
    parser.add_argument(
        "--acquired-on",
        required=True,
        type=date.fromisoformat,
        metavar="YYYY-MM-DD",
        help="Date this exact local dataset snapshot was obtained",
    )
    parser.add_argument("--financial-db-id", default="financial")
    parser.add_argument("--target-count", type=int, default=20)
    parser.add_argument(
        "--output",
        type=Path,
        help=(
            "Output JSON path; default is an ignored local file under "
            "evaluation/datasets/private/bird/"
        ),
    )
    args = parser.parse_args(argv)
    try:
        report = audit_dataset(
            args.dataset_path,
            dialect=args.dialect,
            revision=args.revision,
            acquired_on=args.acquired_on,
            financial_db_id=args.financial_db_id,
            target_count=args.target_count,
        )
        output = args.output or _default_output_path(args.revision)
        if output.exists():
            raise DatasetAuditError(f"Output already exists; choose a new path: {output}")
        output.parent.mkdir(parents=True, exist_ok=True)
        output.write_text(
            json.dumps(report, ensure_ascii=False, indent=2) + "\n",
            encoding="utf-8",
        )
    except (DatasetAuditError, OSError) as error:
        parser.error(str(error))
    print(json.dumps({"report": str(output), **report["summary"]}, ensure_ascii=False, indent=2))
    return 0


def _default_output_path(revision: str) -> Path:
    short_revision = re.sub(r"[^a-zA-Z0-9_-]", "", revision)[:12] or "unversioned"
    timestamp = datetime.now(UTC).strftime("%Y%m%dT%H%M%SZ")
    return (
        Path(__file__).parent
        / "datasets"
        / "private"
        / "bird"
        / f"audit-{short_revision}-{timestamp}.json"
    )


if __name__ == "__main__":
    sys.exit(main())
