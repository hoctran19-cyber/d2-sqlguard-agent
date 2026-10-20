import json
from datetime import date

import pytest
from evaluation.bird_audit import DatasetAuditError, audit_dataset

REVISION = "a" * 40
ACQUIRED_ON = date(2026, 10, 20)


def record(
    question_id,
    *,
    db_id="Financial",
    question="How many accounts are active?",
    sql="SELECT COUNT(*) FROM accounts",
    dialect=None,
    difficulty="simple",
):
    value = {
        "question_id": question_id,
        "db_id": db_id,
        "question": question,
        "SQL": sql,
        "difficulty": difficulty,
    }
    if dialect is not None:
        value["sql_dialect"] = dialect
    return value


def write_dataset(path, records):
    path.write_text(json.dumps(records, ensure_ascii=False), encoding="utf-8")
    return path


def audit(path, **kwargs):
    return audit_dataset(
        path,
        dialect="sqlite",
        revision=REVISION,
        acquired_on=ACQUIRED_ON,
        **kwargs,
    )


def test_audits_financial_rows_and_preserves_source_question_and_gold_sql(tmp_path):
    question = "Show accounts exactly as written: café?"
    gold_sql = "  SELECT COUNT(*)\nFROM accounts; -- source formatting  "
    source = write_dataset(
        tmp_path / "mini_dev_sqlite.json",
        [
            record(7, question=question, sql=gold_sql),
            record(8, db_id="student_club"),
        ],
    )

    report = audit(source)

    assert report["summary"]["total_records"] == 2
    assert report["summary"]["financial_record_count"] == 1
    assert report["summary"]["valid_financial_candidate_count"] == 1
    assert report["financial_records"][0]["question"] == question
    assert report["financial_records"][0]["gold_sql"] == gold_sql
    assert report["summary"]["database_ids"] == ["Financial", "student_club"]
    assert report["candidate_report"]["shortlist"] == []
    assert report["candidate_report"]["candidate_pool"][0]["verification_status"] == "pending"
    assert (
        report["candidate_report"]["candidate_pool"][0]["gold_sql_execution_status"]
        == "not_executed"
    )
    assert report["source"]["revision"] == REVISION
    assert report["source"]["files"][0]["sha256"]
    assert report["accuracy_claim"] is False


def test_missing_dataset_path_has_actionable_error(tmp_path):
    with pytest.raises(DatasetAuditError, match="does not exist"):
        audit(tmp_path / "not-downloaded.json")


@pytest.mark.parametrize(
    ("filename", "contents"),
    [
        ("mini_dev_sqlite.json", '[{"question_id": 1,]'),
        ("mini_dev_sqlite.jsonl", '{"question_id": 1}\nnot-json\n'),
    ],
)
def test_malformed_json_and_jsonl_fail_with_actionable_error(tmp_path, filename, contents):
    source = tmp_path / filename
    source.write_text(contents, encoding="utf-8")

    with pytest.raises(DatasetAuditError, match="not valid UTF-8 JSON/JSONL"):
        audit(source)


def test_explicit_dataset_file_with_conflicting_dialect_marker_is_rejected(tmp_path):
    source = write_dataset(tmp_path / "mini_dev_sqlite.json", [record(1)])

    with pytest.raises(
        DatasetAuditError, match="identifies dialect 'sqlite'.*--dialect is 'postgresql'"
    ):
        audit_dataset(
            source,
            dialect="postgresql",
            revision=REVISION,
            acquired_on=ACQUIRED_ON,
        )


def test_unmarked_explicit_dataset_filename_uses_cli_dialect_assertion(tmp_path):
    source = write_dataset(tmp_path / "export.json", [record(1)])

    report = audit_dataset(
        source,
        dialect="postgresql",
        revision=REVISION,
        acquired_on=ACQUIRED_ON,
    )

    assert report["financial_records"][0]["dialect"] == "postgresql"


def test_reports_missing_and_duplicate_ids_and_excludes_invalid_rows(tmp_path):
    source = write_dataset(
        tmp_path / "records.json",
        [
            record(3),
            record(3, question="Duplicate source identifier"),
            record(None),
        ],
    )

    report = audit(source)

    assert report["summary"]["duplicate_id_count"] == 1
    assert report["summary"]["duplicate_ids"][0]["id"] == 3
    assert report["summary"]["missing_id_count"] == 1
    assert report["summary"]["valid_financial_candidate_count"] == 0
    assert report["candidate_report"]["shortlist"] == []


def test_missing_question_and_gold_sql_are_reported(tmp_path):
    source = write_dataset(
        tmp_path / "records.json",
        [record(1, question=" ", sql=None), record(2, question=None, sql="SELECT 2")],
    )

    report = audit(source)

    assert report["summary"]["missing_question_count"] == 2
    assert report["summary"]["missing_gold_sql_count"] == 1
    assert report["summary"]["valid_financial_candidate_count"] == 0


def test_different_database_id_is_not_silently_selected_as_financial(tmp_path):
    source = write_dataset(
        tmp_path / "records.json",
        [record(1, db_id="finance"), record(2, db_id="financial_other")],
    )

    report = audit(source)

    assert report["summary"]["financial_record_count"] == 0
    assert report["candidate_report"]["shortlist"] == []
    assert report["candidate_report"]["candidate_pool"] == []
    assert report["summary"]["database_ids"] == ["finance", "financial_other"]


def test_unsupported_dialect_is_reported_and_excluded(tmp_path):
    source = write_dataset(
        tmp_path / "records.json",
        [record(1, dialect="oracle")],
    )

    report = audit(source)

    assert report["summary"]["unsupported_sql_dialects"] == [
        {"dialect": "oracle", "record_count": 1}
    ]
    assert report["summary"]["financial_record_count"] == 1
    assert report["summary"]["valid_financial_candidate_count"] == 0


def test_shortlist_is_deterministic_and_pending_with_gold_references(tmp_path):
    rows = [
        record(
            question_id=index,
            question=f"Question {index}",
            sql=(
                f"SELECT account_id FROM accounts WHERE account_id = {index} "
                + (
                    "GROUP BY account_id HAVING COUNT(*) > 1"
                    if index % 2
                    else "ORDER BY account_id"
                )
            ),
            difficulty=("challenging" if index % 3 == 0 else "simple"),
        )
        for index in range(25)
    ]
    source = write_dataset(tmp_path / "mini_dev_sqlite.json", rows)

    first = audit(source)
    second = audit(source)

    first_report = first["candidate_report"]
    second_report = second["candidate_report"]
    assert first_report["selected_count"] == 20
    assert first_report["shortlist"] == second_report["shortlist"]
    assert first_report["candidate_pool"] == []
    assert all(case["verification_status"] == "pending" for case in first_report["shortlist"])
    assert all(
        case["gold_sql_execution_status"] == "not_executed" for case in first_report["shortlist"]
    )
    assert all(
        case["gold_sql_reference"]["dataset_revision"] == REVISION
        and case["gold_sql_reference"]["field"] == "SQL"
        for case in first_report["shortlist"]
    )


@pytest.mark.parametrize("revision", ["", "a" * 12, "g" * 40])
def test_revision_must_be_a_full_hexadecimal_commit_sha(tmp_path, revision):
    source = write_dataset(tmp_path / "records.json", [record(1)])

    with pytest.raises(DatasetAuditError, match="full 40-character hexadecimal commit SHA"):
        audit_dataset(source, dialect="sqlite", revision=revision, acquired_on=ACQUIRED_ON)


def test_valid_full_hexadecimal_commit_sha_is_preserved(tmp_path):
    source = write_dataset(tmp_path / "records.json", [record(1)])
    revision = "0123456789abcdef0123456789abcdef01234567"

    report = audit_dataset(
        source,
        dialect="sqlite",
        revision=revision,
        acquired_on=ACQUIRED_ON,
    )

    assert report["source"]["revision"] == revision


def test_acquisition_date_is_required(tmp_path):
    source = write_dataset(tmp_path / "records.json", [record(1)])
    with pytest.raises(DatasetAuditError, match="Acquisition date is required"):
        audit_dataset(source, dialect="sqlite", revision=REVISION, acquired_on=None)


def test_directory_with_multiple_dialects_selects_matching_upstream_split(tmp_path):
    write_dataset(tmp_path / "mini_dev_sqlite-00000-of-00001.json", [record(1)])
    write_dataset(
        tmp_path / "mini_dev_pg-00000-of-00001.json",
        [record(2, dialect="postgresql")],
    )

    report = audit_dataset(
        tmp_path,
        dialect="postgresql",
        revision=REVISION,
        acquired_on=ACQUIRED_ON,
    )

    assert report["summary"]["total_records"] == 1
    assert report["financial_records"][0]["case_id"] == 2
    assert report["financial_records"][0]["dialect"] == "postgresql"
