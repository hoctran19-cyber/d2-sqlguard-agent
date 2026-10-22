import json
from datetime import date
from pathlib import Path

import pytest

from evaluation.bird_audit import audit_dataset
from evaluation.bird_pilot import (
    PilotInputError,
    _validate_runtime_config,
    load_reviewed_cases,
    run_pilot,
    verify_database,
    verify_sqlite_database,
)
from sqlguard.agent.planning import OllamaPlanner, Plan
from sqlguard.agent.postgres_schema import PostgresSchemaAdapter
from sqlguard.agent.runtime import build_query_runtime_factory
from sqlguard.agent.schema import SchemaColumn, SchemaContext, SchemaTable
from sqlguard.security.policy import load_default_policy
from sqlguard.security.service import QueryResult

REVISION = "b" * 40
POLICY_SHA256 = "c" * 64
QUESTION_SQL = "SELECT customer_id FROM customers"


def _write_sources(directory: Path, dialect: str = "postgresql"):
    dataset = directory / "export.json"
    records = [
        {
            "question_id": case_id,
            "db_id": "Financial",
            "question": f"Reviewed question {case_id}",
            "SQL": f"SELECT {case_id} AS reference_only",
            "sql_dialect": dialect,
        }
        for case_id in range(1, 4)
    ]
    dataset.write_text(json.dumps(records), encoding="utf-8")
    report = audit_dataset(
        dataset,
        dialect=dialect,
        revision=REVISION,
        acquired_on=date(2026, 10, 20),
        target_count=1,
    )
    report_path = directory / "audit.json"
    report_path.write_text(json.dumps(report), encoding="utf-8")
    return report_path, dataset, report


def test_reviewed_cases_are_bound_to_exact_local_dataset_hash_and_text(tmp_path):
    report_path, dataset, _ = _write_sources(tmp_path)

    report, cases = load_reviewed_cases(report_path, [dataset], ["1", "2", "3"])

    assert report["source"]["revision"] == REVISION
    assert [case["case_id"] for case in cases] == ["1", "2", "3"]
    assert cases[0]["question"] == "Reviewed question 1"
    assert "gold_sql" not in cases[0]
    assert cases[0]["gold_sql_reference"]["field"] == "SQL"


def test_missing_dataset_file_fails_explicitly(tmp_path):
    report_path, dataset, _ = _write_sources(tmp_path)

    with pytest.raises(PilotInputError, match="Local BIRD dataset file is missing"):
        load_reviewed_cases(report_path, [dataset.with_name("missing.json")], ["1", "2", "3"])


def test_audit_hash_mismatch_fails_explicitly(tmp_path):
    report_path, dataset, _ = _write_sources(tmp_path)
    dataset.write_text("[]", encoding="utf-8")

    with pytest.raises(PilotInputError, match="does not match the SHA-256"):
        load_reviewed_cases(report_path, [dataset], ["1", "2", "3"])


def test_audit_candidates_are_not_automatically_considered_reviewed(tmp_path):
    report_path, dataset, _ = _write_sources(tmp_path)

    with pytest.raises(PilotInputError, match="explicitly reviewed IDs"):
        load_reviewed_cases(report_path, [dataset], [])


def test_invalid_and_ambiguous_case_ids_fail_explicitly(tmp_path):
    report_path, dataset, _ = _write_sources(tmp_path)

    with pytest.raises(PilotInputError, match="missing or ambiguous"):
        load_reviewed_cases(report_path, [dataset], ["1", "2", "999"])
    with pytest.raises(PilotInputError, match="duplicate IDs"):
        load_reviewed_cases(report_path, [dataset], ["1", "1", "2"])


def test_unsupported_sql_dialect_fails_explicitly(tmp_path):
    report_path, dataset, _ = _write_sources(tmp_path, dialect="sqlite")

    with pytest.raises(PilotInputError, match="requires PostgreSQL"):
        load_reviewed_cases(report_path, [dataset], ["1", "2", "3"])


def test_sqlite_reviewed_cases_keep_sqlite_dialect(tmp_path):
    report_path, dataset, _ = _write_sources(tmp_path, dialect="sqlite")

    _, cases = load_reviewed_cases(report_path, [dataset], ["1", "2", "3"])

    assert all(case["dialect"] == "sqlite" for case in cases)


def test_audit_dialect_cannot_override_source_record_dialect(tmp_path):
    report_path, dataset, report = _write_sources(tmp_path)
    report["financial_records"][0]["dialect"] = "sqlite"
    report_path.write_text(json.dumps(report), encoding="utf-8")

    with pytest.raises(PilotInputError, match="does not match its audited Financial source"):
        load_reviewed_cases(report_path, [dataset], ["1", "2", "3"])


def test_runtime_requires_real_ollama_and_postgres_configuration():
    env = {
        "SQLGUARD_PLANNER": "ollama",
        "SQLGUARD_SCHEMA_SOURCE": "postgres",
        "SQLGUARD_QUERY_SOURCE": "mock",
        "SQLGUARD_DB_DSN_FINANCE": "not-printed",
    }

    with pytest.raises(PilotInputError, match="SQLGUARD_QUERY_SOURCE=postgres"):
        _validate_runtime_config(env, "finance")

    env["SQLGUARD_QUERY_SOURCE"] = "postgres"
    assert _validate_runtime_config(env, "finance") == "not-printed"


def test_runtime_accepts_sqlite_and_rejects_mixed_backends(tmp_path):
    from sqlguard.agent.sqlite_schema import SQLITE_PATH_ENV
    import sqlite3
    database = tmp_path / "financial.sqlite"
    with sqlite3.connect(database):
        pass
    env = {
        "SQLGUARD_PLANNER": "ollama",
        "SQLGUARD_SCHEMA_SOURCE": "sqlite",
        "SQLGUARD_QUERY_SOURCE": "sqlite",
        SQLITE_PATH_ENV: str(database),
    }

    assert _validate_runtime_config(env, "finance") == str(database)
    env["SQLGUARD_SCHEMA_SOURCE"] = "postgres"
    with pytest.raises(PilotInputError, match="matching schema and query backends"):
        _validate_runtime_config(env, "finance")


def test_sqlite_database_marker_is_checked(tmp_path):
    import sqlite3
    database = tmp_path / "financial.sqlite"
    marker = f"sqlguard-bird-pilot:v1; database_id=financial; revision={REVISION}"
    with sqlite3.connect(database) as connection:
        connection.execute(
            "CREATE TABLE sqlguard_bird_pilot_metadata (marker TEXT PRIMARY KEY)"
        )
        connection.execute(
            "INSERT INTO sqlguard_bird_pilot_metadata(marker) VALUES (?)", (marker,)
        )

    verify_sqlite_database(database, "finance", load_default_policy(), "financial", REVISION)


def test_sqlite_database_marker_rejects_wrong_revision(tmp_path):
    import sqlite3
    database = tmp_path / "financial.sqlite"
    with sqlite3.connect(database) as connection:
        connection.execute(
            "CREATE TABLE sqlguard_bird_pilot_metadata (marker TEXT PRIMARY KEY)"
        )
        connection.execute(
            "INSERT INTO sqlguard_bird_pilot_metadata(marker) VALUES (?)",
            ("sqlguard-bird-pilot:v1; database_id=financial; revision=" + "a" * 40,),
        )
    with pytest.raises(PilotInputError, match="does not match the audited BIRD"):
        verify_sqlite_database(database, "finance", load_default_policy(), "financial", REVISION)


def test_unavailable_postgres_is_reported_without_disclosing_dsn_or_exception():
    secret_dsn = "postgresql://user:private-password@localhost/private"

    def unavailable(*_args, **_kwargs):
        raise RuntimeError(f"connection refused for {secret_dsn}")

    with pytest.raises(PilotInputError, match="Cannot verify the PostgreSQL database") as error:
        verify_database(
            secret_dsn,
            "finance",
            load_default_policy(),
            "bird_financial",
            "financial",
            REVISION,
            connector=unavailable,
        )

    assert "private-password" not in str(error.value)


class _FakeOllamaPlanner(OllamaPlanner):
    def __init__(self, policy, schema, sql):
        super().__init__(
            url="http://localhost:11434/api/chat",
            model="test-only",
            schema_context=schema,
            policy=policy,
            role="finance",
        )
        self._sql = sql
        self._repair_sql = None

    async def create_plan(self, question, context):
        del question, context
        return Plan(sql=self._sql, summary="deterministic test plan")

    async def repair_plan(self, question, context, feedback):
        del question, context, feedback
        return Plan(sql=self._repair_sql, summary="deterministic repaired plan")


class _FakePostgresExecutor:
    def __init__(self):
        self.statements = []

    async def execute(self, sql, *, role, timeout_seconds, max_rows):
        self.statements.append((sql, role, timeout_seconds, max_rows))
        return QueryResult(columns=("customer_id",), rows=((1,),))


def test_pilot_uses_postgres_runtime_gate_and_keeps_gold_sql_out_of_planner(tmp_path, monkeypatch):
    report_path, dataset, report = _write_sources(tmp_path)
    _, cases = load_reviewed_cases(report_path, [dataset], ["1", "2", "3"])
    policy = load_default_policy()
    role_schema = SchemaContext(
        tables=(
            SchemaTable(
                "customers",
                tuple(
                    SchemaColumn(column, "text")
                    for column in sorted(policy.allowed_columns("finance", "customers"))
                ),
            ),
            *(
                SchemaTable(
                    table,
                    tuple(
                        SchemaColumn(column, "text")
                        for column in sorted(policy.allowed_columns("finance", table))
                    ),
                )
                for table in sorted(policy.allowed_tables("finance") - {"customers"})
            ),
        ),
        dialect="postgres",
    )
    fake_executor = _FakePostgresExecutor()
    planner = _FakeOllamaPlanner(policy, role_schema, QUESTION_SQL)
    monkeypatch.setattr("evaluation.bird_pilot.verify_database", lambda *args, **kwargs: None)
    monkeypatch.setattr(
        PostgresSchemaAdapter,
        "from_env",
        classmethod(
            lambda cls, policy, env: type(
                "SchemaLoader",
                (),
                {"load_sync": lambda self, role: role_schema},
            )()
        ),
    )
    monkeypatch.setattr("evaluation.bird_pilot.create_planner", lambda env: planner)
    monkeypatch.setattr(
        "evaluation.bird_pilot.create_planner_for_role",
        lambda *args, **kwargs: _async_return(planner),
    )
    original_factory = build_query_runtime_factory

    def postgres_factory(role, env, *, policy, audit):
        assert env["SQLGUARD_QUERY_SOURCE"] == "postgres"
        return original_factory(
            role,
            env,
            executor=fake_executor,
            audit=audit,
            policy=policy,
        )

    monkeypatch.setattr("evaluation.bird_pilot.build_query_runtime_factory", postgres_factory)
    env = {
        "SQLGUARD_PLANNER": "ollama",
        "SQLGUARD_SCHEMA_SOURCE": "postgres",
        "SQLGUARD_QUERY_SOURCE": "postgres",
        "SQLGUARD_DB_DSN_FINANCE": "postgresql://local/test",
    }

    artifact_path = run_pilot(
        report,
        cases,
        role="finance",
        policy=policy,
        policy_sha256=POLICY_SHA256,
        env=env,
        database_name="bird_financial",
        output_root=tmp_path / "private-output",
    )

    artifact_text = artifact_path.read_text(encoding="utf-8")
    artifact = json.loads(artifact_text)
    assert artifact["cases"][0]["execution_status"] == "succeeded"
    assert artifact["cases"][0]["generated_sql"] == [QUESTION_SQL]
    assert artifact["cases"][0]["result_rows"] == [[1]]
    assert artifact["cases"][0]["result_correctness"] == "not_evaluated"
    assert artifact["cases"][0]["security_policy_compliance"] == "compliant"
    assert artifact["policy_sha256"] == POLICY_SHA256
    assert fake_executor.statements[0][1] == "finance"
    assert all(
        f"SELECT {case_id} AS reference_only" not in artifact_text for case_id in range(1, 4)
    )

    planner._sql = "SELECT identity_number FROM customers"
    denied_path = run_pilot(
        report,
        cases,
        role="finance",
        policy=policy,
        policy_sha256=POLICY_SHA256,
        env=env,
        database_name="bird_financial",
        output_root=tmp_path / "private-output",
    )
    denied = json.loads(denied_path.read_text(encoding="utf-8"))["cases"][0]
    assert denied["execution_status"] == "failed"
    assert denied["error_category"] == "security_rejection"
    assert denied["gate_decisions"][0]["allowed"] is False
    assert denied["tool_call_count"] == 0
    assert len(fake_executor.statements) == 3

    planner._sql = "SELECT missing_column FROM customers"
    planner._repair_sql = QUESTION_SQL
    repaired_path = run_pilot(
        report,
        cases,
        role="finance",
        policy=policy,
        policy_sha256=POLICY_SHA256,
        env=env,
        database_name="bird_financial",
        output_root=tmp_path / "private-output",
    )
    repaired = json.loads(repaired_path.read_text(encoding="utf-8"))["cases"][0]
    assert repaired["generated_sql"] == ["SELECT missing_column FROM customers", QUESTION_SQL]
    assert [entry["allowed"] for entry in repaired["gate_decisions"]] == [False, True]
    assert repaired["llm_call_count"] == 2
    assert repaired["sql_attempt_count"] == 2
    assert repaired["tool_call_count"] == 1
    assert fake_executor.statements[-1][0] == "SELECT customer_id FROM customers LIMIT 100"


async def _async_return(value):
    return value
