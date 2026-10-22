"""Run a small, explicitly reviewed BIRD Financial pilot through SQLGuard."""

from __future__ import annotations

import argparse
import asyncio
import hashlib
import json
import os
import re
import sqlite3
import sys
from collections.abc import Callable, Mapping
from dataclasses import asdict
from datetime import UTC, datetime
from pathlib import Path
from time import perf_counter
from typing import Any
from uuid import uuid4

from evaluation.bird_audit import SUPPORTED_DIALECTS, _normalize_dialect, _read_records
from sqlguard.agent.controller import AgentController, RunScope
from sqlguard.agent.models import AgentRequest, ExecutionBudget
from sqlguard.agent.planning import OllamaPlanner, PlannerConfigError, create_planner
from sqlguard.agent.postgres_schema import PostgresSchemaAdapter, SchemaAdapterError
from sqlguard.agent.sqlite_schema import SQLITE_PATH_ENV, SQLiteSchemaAdapter
from sqlguard.agent.runtime import (
    QUERY_SOURCE_ENV,
    SCHEMA_SOURCE_ENV,
    QueryRuntimeError,
    QueryRuntimeFactory,
    build_query_runtime_factory,
    create_planner_for_role,
)
from sqlguard.agent.schema import SchemaContext
from sqlguard.mcp.tools import InProcessToolRegistry
from sqlguard.memory.store import InMemoryMemory
from sqlguard.observability.events import Event, InMemoryEventSink
from sqlguard.security.audit import AuditRecord, InMemoryAuditSink
from sqlguard.security.gate import PolicySQLGate, ReadOnlySQLGate, SecurityDecision
from sqlguard.security.policy import RolePolicy
from sqlguard.security.postgres import DSN_ENV_PREFIX

_SHA256_PATTERN = re.compile(r"[0-9a-fA-F]{64}")
_REVISION_PATTERN = re.compile(r"[0-9a-fA-F]{40}")
_RUNTIME_LOGINS = {
    "sales": "sqlguard_sales_app",
    "finance": "sqlguard_finance_app",
    "operations": "sqlguard_ops_app",
}
_DEFAULT_OUTPUT_ROOT = Path(__file__).parent / "datasets" / "private" / "bird" / "pilot-runs"


class PilotInputError(ValueError):
    """An actionable local input, configuration, or database preflight failure."""


class _RecordingGate:
    def __init__(self, gate: PolicySQLGate) -> None:
        self._gate = gate
        self.decisions: list[dict[str, Any]] = []

    def check(self, sql: str) -> SecurityDecision:
        decision = self._gate.check(sql)
        self.decisions.append(
            {
                "sql": sql,
                "allowed": decision.allowed,
                "violation_codes": list(decision.violations),
            }
        )
        return decision


class _CapturingToolRegistry:
    def __init__(self, tools: InProcessToolRegistry) -> None:
        self._tools = tools
        self.sql_inputs: list[str] = []
        self.results: list[dict[str, Any]] = []

    async def call(self, name: str, arguments: dict[str, Any], *, timeout_seconds: float) -> Any:
        sql = arguments.get("sql")
        if name == "query" and isinstance(sql, str):
            self.sql_inputs.append(sql)
        output = await self._tools.call(name, arguments, timeout_seconds=timeout_seconds)
        if name == "query" and isinstance(output, dict):
            self.results.append(output)
        return output


class _FixedSchemaLoader:
    def __init__(self, schema: SchemaContext) -> None:
        self._schema = schema

    async def load(self, role: str) -> SchemaContext:
        del role
        return self._schema


def load_reviewed_cases(
    audit_path: str | Path,
    dataset_paths: list[str | Path],
    reviewed_ids: list[str],
) -> tuple[dict[str, Any], list[dict[str, Any]]]:
    """Verify selected questions against the exact locally audited source files."""
    audit_file = Path(audit_path)
    if not audit_file.is_file():
        raise PilotInputError(f"Audit report is missing: {audit_file}")
    if not dataset_paths:
        raise PilotInputError("Provide at least one local source dataset file with --dataset-file.")
    if not reviewed_ids or not 3 <= len(reviewed_ids) <= 5:
        raise PilotInputError("Provide 3 to 5 explicitly reviewed IDs with --reviewed-ids.")
    if len(set(reviewed_ids)) != len(reviewed_ids):
        raise PilotInputError("--reviewed-ids contains duplicate IDs.")

    try:
        audit = json.loads(audit_file.read_text(encoding="utf-8"))
    except (OSError, UnicodeError, json.JSONDecodeError):
        raise PilotInputError("Cannot read a valid local BIRD audit JSON report.") from None
    if (
        not isinstance(audit, dict)
        or audit.get("report_type") != "bird_dataset_audit_not_execution_accuracy"
    ):
        raise PilotInputError("The input is not a supported BIRD dataset audit report.")
    source = audit.get("source")
    revision = source.get("revision") if isinstance(source, dict) else None
    if not isinstance(revision, str) or _REVISION_PATTERN.fullmatch(revision) is None:
        raise PilotInputError("Audit report must record a full 40-character source revision SHA.")

    source_files = source.get("files")
    if not isinstance(source_files, list):
        raise PilotInputError("Audit report has no source file hashes; regenerate the audit.")
    records_by_source: dict[str, list[dict[str, Any]]] = {}
    source_file_by_name: dict[str, dict[str, Any]] = {}
    for entry in source_files:
        if not isinstance(entry, dict) or not isinstance(entry.get("file"), str):
            raise PilotInputError("Audit report has malformed source file references.")
        name = entry["file"]
        if name in source_file_by_name:
            raise PilotInputError("Audit report has duplicate source file names.")
        source_file_by_name[name] = entry

    supplied_files: dict[str, Path] = {}
    for value in dataset_paths:
        path = Path(value)
        if not path.is_file():
            raise PilotInputError(f"Local BIRD dataset file is missing: {path}")
        if path.suffix.lower() not in {".json", ".jsonl"}:
            raise PilotInputError(f"Unsupported local dataset format: {path.suffix or '(none)'}.")
        if path.name not in source_file_by_name or path.name in supplied_files:
            raise PilotInputError(
                f"Dataset file {path.name!r} is not a unique source file in this audit report."
            )
        expected_hash = source_file_by_name[path.name].get("sha256")
        try:
            actual_hash = hashlib.sha256(path.read_bytes()).hexdigest()
        except OSError:
            raise PilotInputError(f"Cannot read local BIRD dataset file {path.name!r}.") from None
        if (
            not isinstance(expected_hash, str)
            or _SHA256_PATTERN.fullmatch(expected_hash) is None
            or actual_hash.casefold() != expected_hash.casefold()
        ):
            raise PilotInputError(
                f"Dataset file {path.name!r} does not match the SHA-256 recorded by the audit."
            )
        try:
            indexed_records = _read_records(path)
            verified_hash = hashlib.sha256(path.read_bytes()).hexdigest()
        except ValueError:
            raise PilotInputError(f"Cannot parse audited dataset file {path.name!r}.") from None
        except OSError:
            raise PilotInputError(f"Cannot read local BIRD dataset file {path.name!r}.") from None
        if verified_hash.casefold() != actual_hash.casefold():
            raise PilotInputError(f"Dataset file {path.name!r} changed during pilot validation.")
        records_by_source[path.name] = [row for _, row in indexed_records]
        supplied_files[path.name] = path

    financial_id = None
    summary = audit.get("summary")
    if isinstance(summary, dict):
        financial_id = summary.get("financial_db_id")
    if not isinstance(financial_id, str) or not financial_id.strip():
        raise PilotInputError("Audit report does not identify its Financial database ID.")

    audited_records = audit.get("financial_records")
    if not isinstance(audited_records, list):
        raise PilotInputError("Audit report has no Financial source records.")
    selected: list[dict[str, Any]] = []
    for case_id in reviewed_ids:
        matches = [
            row
            for row in audited_records
            if isinstance(row, dict) and str(row.get("case_id")) == case_id
        ]
        if len(matches) != 1:
            raise PilotInputError(f"Reviewed case ID {case_id!r} is missing or ambiguous.")
        row = matches[0]
        source_ref = row.get("source")
        if (
            not isinstance(source_ref, dict)
            or not isinstance(source_ref.get("file"), str)
            or not isinstance(source_ref.get("record_index"), int)
            or source_ref["file"] not in supplied_files
        ):
            raise PilotInputError(
                f"Reviewed case {case_id!r} requires its exact audited source file via "
                "--dataset-file."
            )
        source_rows = records_by_source[source_ref["file"]]
        index = source_ref["record_index"]
        if index < 0 or index >= len(source_rows):
            raise PilotInputError(f"Reviewed case {case_id!r} has an invalid source record index.")
        original = source_rows[index]
        source_id = original.get("question_id", original.get("id"))
        original_dialect = original.get("sql_dialect", original.get("dialect"))
        dialect_mismatch = not _is_missing_dialect(original_dialect) and _normalize_dialect(
            str(original_dialect)
        ) != row.get("dialect")
        if (
            str(source_id) != case_id
            or original.get("db_id") != row.get("db_id")
            or original.get("question") != row.get("question")
            or original.get("SQL") != row.get("gold_sql")
            or not isinstance(row.get("db_id"), str)
            or row["db_id"].casefold() != financial_id.casefold()
            or dialect_mismatch
            or not isinstance(row.get("question"), str)
            or not row["question"].strip()
            or not isinstance(row.get("gold_sql"), str)
            or not row["gold_sql"].strip()
        ):
            raise PilotInputError(
                f"Reviewed case {case_id!r} does not match its audited Financial source record."
            )
        if row.get("missing_question") or row.get("missing_gold_sql"):
            raise PilotInputError(f"Reviewed case {case_id!r} is incomplete in the audit.")
        dialect = row.get("dialect")
        if dialect not in SUPPORTED_DIALECTS:
            raise PilotInputError(f"Reviewed case {case_id!r} has unsupported dialect {dialect!r}.")
        if dialect not in {"postgresql", "sqlite"}:
            raise PilotInputError(
                f"Reviewed case {case_id!r} uses {dialect!r}; the pilot requires PostgreSQL "
                "or SQLite Financial source questions and does not translate SQL dialects."
            )
        selected.append(
            {
                "case_id": case_id,
                "question": row["question"],
                "database_id": row["db_id"],
                "dialect": dialect,
                "source_reference": {
                    "revision": revision,
                    "file": source_ref["file"],
                    "record_index": index,
                },
                "gold_sql_reference": {
                    "revision": revision,
                    "file": source_ref["file"],
                    "record_id": case_id,
                    "field": "SQL",
                },
            }
        )
    return audit, selected


def load_role_policy(path: str | Path, role: str) -> tuple[RolePolicy, str]:
    policy_path = Path(path)
    if not policy_path.is_file():
        raise PilotInputError(
            f"Reviewed BIRD role policy is missing: {policy_path}. "
            "Provide a policy and matching least-privilege PostgreSQL grants."
        )
    try:
        contents = policy_path.read_bytes()
        policy = RolePolicy.from_dict(json.loads(contents))
    except (OSError, UnicodeError, json.JSONDecodeError, ValueError, TypeError):
        raise PilotInputError("Cannot load a valid SQLGuard BIRD role policy JSON.") from None
    if not policy.has_role(role):
        raise PilotInputError(f"Role {role!r} is not defined in the supplied BIRD role policy.")
    return policy, hashlib.sha256(contents).hexdigest()


def _validate_runtime_config(env: Mapping[str, str], role: str) -> str:
    if role not in _RUNTIME_LOGINS:
        raise PilotInputError("Pilot role must be one of sales, finance, or operations.")
    if env.get("SQLGUARD_PLANNER", "").casefold() != "ollama":
        raise PilotInputError("Set SQLGUARD_PLANNER=ollama; the pilot has no planner fallback.")
    schema_source = env.get(SCHEMA_SOURCE_ENV, "").casefold()
    query_source = env.get(QUERY_SOURCE_ENV, "").casefold()
    if schema_source not in {"postgres", "sqlite"}:
        raise PilotInputError(f"Set {SCHEMA_SOURCE_ENV}=postgres or sqlite; schema must be loaded from DB.")
    if query_source not in {"postgres", "sqlite"}:
        raise PilotInputError(f"Set {QUERY_SOURCE_ENV}=postgres or sqlite; mock tools are not supported.")
    if schema_source != query_source:
        raise PilotInputError("BIRD pilot requires matching schema and query backends.")
    if query_source == "sqlite":
        path = env.get(SQLITE_PATH_ENV)
        if not path or not path.strip():
            raise PilotInputError(f"Set {SQLITE_PATH_ENV} to the local BIRD SQLite database file.")
        if not Path(path).expanduser().is_file():
            raise PilotInputError(f"SQLite database file configured by {SQLITE_PATH_ENV} does not exist.")
        return path
    dsn = env.get(DSN_ENV_PREFIX + role.upper())
    if not dsn:
        raise PilotInputError(
            f"Set {DSN_ENV_PREFIX + role.upper()} to the selected role's PostgreSQL DSN."
        )
    return dsn


def verify_database(
    dsn: str,
    role: str,
    policy: RolePolicy,
    expected_database: str,
    expected_database_id: str,
    revision: str,
    *,
    connector: Callable[..., Any] | None = None,
) -> None:
    """Check the selected connection identity and exact read-only privileges."""
    if connector is None:
        try:
            import psycopg
        except ImportError:
            raise PilotInputError(
                "PostgreSQL driver is unavailable; install the project postgres extra."
            ) from None
        connector = psycopg.connect
    try:
        connection = connector(dsn, connect_timeout=5)
        with connection, connection.cursor() as cursor:
            cursor.execute(
                "SELECT current_user, current_database(), "
                "(SELECT rolsuper FROM pg_roles WHERE rolname = current_user), "
                "(SELECT rolcreatedb FROM pg_roles WHERE rolname = current_user), "
                "(SELECT rolcreaterole FROM pg_roles WHERE rolname = current_user), "
                "(SELECT rolreplication FROM pg_roles WHERE rolname = current_user), "
                "(SELECT rolbypassrls FROM pg_roles WHERE rolname = current_user), "
                "(SELECT rolcanlogin FROM pg_roles WHERE rolname = current_user)"
            )
            identity = cursor.fetchone()
            if identity != (
                _RUNTIME_LOGINS[role],
                expected_database,
                False,
                False,
                False,
                False,
                False,
                True,
            ):
                raise PilotInputError(
                    "Connected PostgreSQL user/database does not match the selected runtime "
                    "role and --database-name; use the local BIRD Financial database and "
                    "least-privilege login."
                )
            cursor.execute(
                "SELECT obj_description(to_regclass(%s), 'pg_class')",
                ("public.sqlguard_bird_pilot_metadata",),
            )
            expected_marker = (
                f"sqlguard-bird-pilot:v1; database_id={expected_database_id}; revision={revision}"
            )
            if cursor.fetchone()[0] != expected_marker:
                raise PilotInputError(
                    "PostgreSQL database is not marked for this exact BIRD database ID and "
                    "source revision. Load and review the actual BIRD database, then configure "
                    "the local pilot metadata marker described in the BIRD README."
                )
            cursor.execute(
                "SELECT has_table_privilege(current_user, %s, 'SELECT'), "
                "has_table_privilege(current_user, %s, 'INSERT'), "
                "has_table_privilege(current_user, %s, 'UPDATE'), "
                "has_table_privilege(current_user, %s, 'DELETE'), "
                "has_table_privilege(current_user, %s, 'TRUNCATE'), "
                "has_table_privilege(current_user, %s, 'REFERENCES'), "
                "has_table_privilege(current_user, %s, 'TRIGGER'), "
                "has_column_privilege(current_user, %s, 'marker', 'SELECT'), "
                "has_column_privilege(current_user, %s, 'marker', 'INSERT'), "
                "has_column_privilege(current_user, %s, 'marker', 'UPDATE'), "
                "has_column_privilege(current_user, %s, 'marker', 'REFERENCES')",
                (
                    "public.sqlguard_bird_pilot_metadata",
                    "public.sqlguard_bird_pilot_metadata",
                    "public.sqlguard_bird_pilot_metadata",
                    "public.sqlguard_bird_pilot_metadata",
                    "public.sqlguard_bird_pilot_metadata",
                    "public.sqlguard_bird_pilot_metadata",
                    "public.sqlguard_bird_pilot_metadata",
                    "public.sqlguard_bird_pilot_metadata",
                    "public.sqlguard_bird_pilot_metadata",
                    "public.sqlguard_bird_pilot_metadata",
                    "public.sqlguard_bird_pilot_metadata",
                ),
            )
            if any(cursor.fetchone()):
                raise PilotInputError(
                    "The runtime role must not be granted any access to the pilot metadata table."
                )
            cursor.execute(
                "SELECT has_schema_privilege(current_user, %s, 'CREATE')",
                (policy.schema,),
            )
            if cursor.fetchone()[0]:
                raise PilotInputError(
                    "PostgreSQL runtime role must not have CREATE privileges on its data schema."
                )
            cursor.execute(
                "SELECT current_setting('default_transaction_read_only') = 'on', "
                "current_schemas(false), "
                "current_setting('statement_timeout')::interval > interval '0', "
                "current_setting('statement_timeout')::interval <= "
                "%s * interval '1 second'",
                (policy.limits.query_timeout_seconds,),
            )
            read_only, search_path, has_timeout, timeout_within_policy = cursor.fetchone()
            if (
                not read_only
                or search_path != [policy.schema]
                or not has_timeout
                or not timeout_within_policy
            ):
                raise PilotInputError(
                    "PostgreSQL runtime role must use a read-only session, only the selected "
                    "schema in search_path, and a statement timeout within policy limits."
                )
            cursor.execute(
                "SELECT table_name FROM information_schema.tables "
                "WHERE table_schema = %s AND table_type = 'BASE TABLE'",
                (policy.schema,),
            )
            visible_tables = {row[0].casefold() for row in cursor.fetchall()}
            expected_tables = set(policy.allowed_tables(role))
            if visible_tables != expected_tables:
                raise PilotInputError(
                    "PostgreSQL-visible tables do not exactly match the selected role policy."
                )
            for table, columns in policy.tables.items():
                table_name = f"{policy.schema}.{table}"
                for column in columns:
                    cursor.execute(
                        "SELECT has_column_privilege(current_user, %s, %s, 'SELECT'), "
                        "has_column_privilege(current_user, %s, %s, 'INSERT'), "
                        "has_column_privilege(current_user, %s, %s, 'UPDATE'), "
                        "has_column_privilege(current_user, %s, %s, 'REFERENCES')",
                        (
                            table_name,
                            column,
                            table_name,
                            column,
                            table_name,
                            column,
                            table_name,
                            column,
                        ),
                    )
                    actual_select, actual_insert, actual_update, actual_references = (
                        cursor.fetchone()
                    )
                    if actual_select != policy.can_read(role, table, column) or any(
                        (actual_insert, actual_update, actual_references)
                    ):
                        raise PilotInputError(
                            "PostgreSQL column privileges do not exactly match the selected "
                            "role policy."
                        )
                for privilege in (
                    "INSERT",
                    "UPDATE",
                    "DELETE",
                    "TRUNCATE",
                    "REFERENCES",
                    "TRIGGER",
                ):
                    cursor.execute(
                        "SELECT has_table_privilege(current_user, %s, %s)",
                        (table_name, privilege),
                    )
                    if cursor.fetchone()[0]:
                        raise PilotInputError(
                            "PostgreSQL runtime role has a write or elevated table privilege."
                        )
            cursor.execute(
                "SELECT has_database_privilege(current_user, current_database(), 'CREATE'), "
                "has_database_privilege(current_user, current_database(), 'TEMP')"
            )
            if any(cursor.fetchone()):
                raise PilotInputError(
                    "PostgreSQL runtime role must not have CREATE or TEMP database privileges."
                )
            for function in (
                "pg_sleep(double precision)",
                "pg_sleep_for(interval)",
                "pg_sleep_until(timestamp with time zone)",
            ):
                cursor.execute(
                    "SELECT has_function_privilege(current_user, %s, 'EXECUTE')", (function,)
                )
                if cursor.fetchone()[0]:
                    raise PilotInputError(
                        "PostgreSQL runtime role can execute a prohibited sleep function."
                    )
    except PilotInputError:
        raise
    except Exception:
        raise PilotInputError(
            "Cannot verify the PostgreSQL database or role grants; check local DB availability, "
            "database name, driver, and grants without exposing connection details."
        ) from None


def verify_sqlite_database(
    path: str | Path,
    role: str,
    policy: RolePolicy,
    expected_database_id: str,
    revision: str,
) -> None:
    """Verify the SQLite file and operator-maintained provenance marker in read-only mode.

    SQLite has no PostgreSQL-style roles/grants; OS file permissions are a separate boundary.
    """
    database = Path(path).expanduser()
    if not database.is_file():
        raise PilotInputError("Configured BIRD SQLite database file does not exist.")
    uri = f"{database.resolve().as_uri()}?mode=ro"
    expected_marker = (
        f"sqlguard-bird-pilot:v1; database_id={expected_database_id}; revision={revision}"
    )
    try:
        with sqlite3.connect(uri, uri=True, timeout=5) as connection:
            connection.execute("PRAGMA query_only = ON")
            tables = {
                row[0]
                for row in connection.execute(
                    "SELECT name FROM sqlite_master WHERE type='table'"
                )
            }
            marker_table = "sqlguard_bird_pilot_metadata"
            if marker_table not in tables or marker_table in policy.tables:
                raise PilotInputError(
                    "SQLite database must contain a metadata table excluded from the role policy."
                )
            columns = {
                row[1]
                for row in connection.execute(f'PRAGMA table_info("{marker_table}")')
            }
            if columns != {"marker"}:
                raise PilotInputError("SQLite BIRD metadata table must contain only a marker column.")
            markers = list(connection.execute(f'SELECT marker FROM "{marker_table}"'))
            if markers != [(expected_marker,)]:
                raise PilotInputError(
                    "SQLite database marker does not match the audited BIRD database ID and "
                    "source revision; review the database and marker described in the BIRD README."
                )
            if not policy.has_role(role):
                raise PilotInputError(f"Role {role!r} is not present in the supplied BIRD policy.")
    except PilotInputError:
        raise
    except sqlite3.Error:
        raise PilotInputError(
            "Cannot verify the read-only SQLite database or its metadata marker; check the "
            "database file and marker without exposing database contents."
        ) from None


def _schema_matches_policy(schema: SchemaContext, policy: RolePolicy, role: str) -> bool:
    visible = {
        table.name.casefold(): {column.name.casefold() for column in table.columns}
        for table in schema.tables
    }
    expected = {
        table: set(policy.allowed_columns(role, table)) for table in policy.allowed_tables(role)
    }
    return visible == expected


def _is_missing_dialect(value: Any) -> bool:
    return value is None or (isinstance(value, str) and not value.strip())


def _event_data(event: Event) -> dict[str, Any]:
    return {
        "event_type": event.event_type,
        "timestamp": event.timestamp.isoformat(),
        "status": event.status,
        "duration_ms": event.duration_ms,
        "error_category": event.error_category,
    }


def _audit_data(record: AuditRecord) -> dict[str, Any]:
    return json.loads(record.to_json())


async def _run_case(
    case: dict[str, Any],
    *,
    role: str,
    policy: RolePolicy,
    env: Mapping[str, str],
    schema: SchemaContext,
    runtime_factory: Any,
    audit_sink: InMemoryAuditSink,
    budget: ExecutionBudget,
) -> dict[str, Any]:
    planner = await create_planner_for_role(
        role,
        env,
        schema_loader=_FixedSchemaLoader(schema),
        policy=policy,
    )
    if not isinstance(planner, OllamaPlanner):
        raise PilotInputError("Pilot planner selection did not produce OllamaPlanner.")

    events = InMemoryEventSink()
    recording_gates: list[_RecordingGate] = []
    tool_registry: _CapturingToolRegistry | None = None

    def scope_factory(run_id: str) -> RunScope:
        nonlocal tool_registry
        runtime = runtime_factory.for_run(run_id)
        recorded_gate = _RecordingGate(runtime.gate)
        recording_gates.append(recorded_gate)
        tool_registry = _CapturingToolRegistry(InProcessToolRegistry([runtime.tool]))
        return RunScope(recorded_gate, tool_registry, output_check=runtime.output_check)

    controller = AgentController(
        planner=planner,
        tools=InProcessToolRegistry([]),
        security_gate=ReadOnlySQLGate(),
        memory=InMemoryMemory(),
        events=events,
        budget=budget,
        run_scope_factory=scope_factory,
    )
    started = perf_counter()
    result = await controller.run(AgentRequest(question=case["question"]))
    latency_ms = (perf_counter() - started) * 1000
    gate_decisions = [
        decision for recorded_gate in recording_gates for decision in recorded_gate.decisions
    ]
    tool_results = tool_registry.results if tool_registry is not None else []
    executed = bool(tool_results)
    allowed_sql = {row["sql"] for row in gate_decisions if row["allowed"]}
    attempted_sql = tool_registry.sql_inputs if tool_registry is not None else []
    security_compliant = all(sql in allowed_sql for sql in attempted_sql)
    tool_output = tool_results[-1] if tool_results else None
    return {
        "case_id": case["case_id"],
        "source_revision": case["source_reference"]["revision"],
        "source_reference": case["source_reference"],
        "database_id": case["database_id"],
        "sql_dialect": case["dialect"],
        "question": case["question"],
        "selected_role": role,
        "sql_generation_success": bool(gate_decisions),
        "generated_sql": [entry["sql"] for entry in gate_decisions],
        "gate_decisions": gate_decisions,
        "execution_status": "succeeded" if executed else "failed",
        "error_category": result.state.failure_reason,
        "result_rows": tool_output.get("rows", []) if tool_output else [],
        "result_summary": (
            {
                "row_count": tool_output.get("row_count", 0),
                "truncated": tool_output.get("truncated", False),
                "columns": tool_output.get("columns", []),
            }
            if tool_output
            else None
        ),
        "latency_ms": round(latency_ms, 3),
        "agent_run_id": result.state.run_id,
        "sql_attempt_count": result.state.sql_attempt_count,
        "llm_call_count": result.state.llm_call_count,
        "tool_call_count": result.state.tool_call_count,
        "retry_count": result.state.retry_count,
        "trace_reference": result.state.run_id,
        "trace": [_event_data(event) for event in events.events],
        "audit_records": [_audit_data(record) for record in audit_sink.records],
        "gold_sql_reference": case["gold_sql_reference"],
        "result_comparison": "not_evaluated",
        "result_correctness": "not_evaluated",
        "security_policy_compliance": (
            "not_evaluated"
            if not gate_decisions
            else "compliant"
            if security_compliant
            else "violation"
        ),
        "controller_status": result.state.status.value,
    }


def run_pilot(
    audit: dict[str, Any],
    cases: list[dict[str, Any]],
    *,
    role: str,
    policy: RolePolicy,
    policy_sha256: str,
    env: Mapping[str, str],
    database_name: str,
    output_root: Path = _DEFAULT_OUTPUT_ROOT,
) -> Path:
    """Run selected cases on Ollama + role-filtered PostgreSQL and persist private artifacts."""
    if not isinstance(audit, dict) or not isinstance(audit.get("source"), dict):
        raise PilotInputError("A valid BIRD audit report is required.")
    summary = audit.get("summary")
    if not isinstance(summary, dict):
        raise PilotInputError("BIRD audit report has no summary metadata.")
    expected_database_id = summary.get("financial_db_id")
    revision = audit["source"].get("revision")
    if (
        not isinstance(expected_database_id, str)
        or not expected_database_id.strip()
        or not isinstance(revision, str)
        or _REVISION_PATTERN.fullmatch(revision) is None
    ):
        raise PilotInputError("BIRD audit report lacks its Financial database ID or source SHA.")
    if _SHA256_PATTERN.fullmatch(policy_sha256) is None:
        raise PilotInputError("A full SHA-256 digest of the selected role policy is required.")
    if not isinstance(cases, list) or any(not isinstance(case, dict) for case in cases):
        raise PilotInputError("Selected reviewed cases must be a list of audit records.")
    case_ids = [case.get("case_id") for case in cases]
    if (
        not 3 <= len(cases) <= 5
        or any(not isinstance(case_id, str) or not case_id for case_id in case_ids)
        or len(set(case_ids)) != len(cases)
    ):
        raise PilotInputError("Pilot runs require 3 to 5 unique reviewed case IDs.")
    if any(
        not isinstance(case.get("question"), str)
        or not case["question"].strip()
        or not isinstance(case.get("source_reference"), dict)
        or not isinstance(case.get("gold_sql_reference"), dict)
        for case in cases
    ):
        raise PilotInputError("Selected cases are missing questions or source references.")
    backend = env.get(QUERY_SOURCE_ENV, "").casefold()
    expected_dialect = "postgresql" if backend == "postgres" else "sqlite"
    if any(
        not isinstance(case.get("database_id"), str)
        or case["database_id"].casefold() != expected_database_id.casefold()
        or case.get("dialect") != expected_dialect
        for case in cases
    ):
        raise PilotInputError(
            "Every selected case must belong to the audited Financial database and use the "
            "same dialect as the selected PostgreSQL or SQLite backend."
        )
    database_locator = _validate_runtime_config(env, role)
    if not isinstance(database_name, str) or not database_name.strip():
        raise PilotInputError("Provide a logical --database-name for the selected BIRD database.")
    if not policy.has_role(role):
        raise PilotInputError(f"Role {role!r} is not present in the supplied BIRD policy.")
    if backend == "postgres":
        verify_database(
            database_locator, role, policy, database_name, expected_database_id, revision
        )
        try:
            schema_adapter = PostgresSchemaAdapter.from_env(policy=policy, env=env)
            schema = schema_adapter.load_sync(role)
        except SchemaAdapterError as error:
            raise PilotInputError(
                f"Cannot load the selected role's PostgreSQL schema ({error.category}); "
                "check the BIRD database and grants."
            ) from None
    else:
        verify_sqlite_database(
            database_locator, role, policy, expected_database_id, revision
        )
        try:
            schema_adapter = SQLiteSchemaAdapter.from_env(policy=policy, env=env)
            schema = schema_adapter.load_sync(role)
        except SchemaAdapterError as error:
            raise PilotInputError(
                f"Cannot load the selected role's SQLite schema ({error.category}); "
                "check the BIRD database file and role policy."
            ) from None
    if not _schema_matches_policy(schema, policy, role):
        raise PilotInputError(
            f"Loaded {backend} schema does not exactly match the selected role policy."
        )

    try:
        planner = create_planner(env)
    except PlannerConfigError as error:
        raise PilotInputError(f"Invalid Ollama planner configuration: {error}") from None
    if not isinstance(planner, OllamaPlanner):
        raise PilotInputError("Set SQLGUARD_PLANNER=ollama; no demo or mock planner is allowed.")
    runtime_factory: QueryRuntimeFactory | None
    try:
        pilot_audit = InMemoryAuditSink()
        runtime_factory = build_query_runtime_factory(
            role,
            env,
            policy=policy,
            audit=pilot_audit,
        )
    except QueryRuntimeError as error:
        raise PilotInputError(
            f"Cannot build the {backend} runtime ({error.category}); check role configuration."
        ) from None
    if runtime_factory is None:
        raise PilotInputError("A real PostgreSQL or SQLite query runtime is required; mock mode is not supported.")
    if not isinstance(runtime_factory.audit, InMemoryAuditSink):
        raise PilotInputError("Pilot requires an in-memory, redacted audit sink.")

    run_id = str(uuid4())
    run_directory = output_root / run_id
    try:
        run_directory.mkdir(mode=0o700, parents=True, exist_ok=False)
    except FileExistsError:
        raise PilotInputError("Pilot run ID collision; rerun to create a unique output directory.")
    except OSError:
        raise PilotInputError(
            "Cannot create the ignored local pilot output directory; check filesystem permissions."
        ) from None

    budget = ExecutionBudget()
    case_results = []
    for case in cases:
        audit_sink = runtime_factory.audit
        audit_sink.records.clear()
        case_result = asyncio.run(
            _run_case(
                case,
                role=role,
                policy=policy,
                env=env,
                schema=schema,
                runtime_factory=runtime_factory,
                audit_sink=audit_sink,
                budget=budget,
            )
        )
        case_results.append(case_result)

    artifact = {
        "schema_version": 1,
        "artifact_type": "bird_financial_sqlguard_pilot_not_benchmark_accuracy",
        "pilot_run_id": run_id,
        "created_at_utc": datetime.now(UTC).isoformat(),
        "source_revision": revision,
        "acquisition_date": audit.get("acquisition_date"),
        "source_files": audit["source"]["files"],
        "database_id": expected_database_id,
        "database_backend": backend,
        "database_name": database_name,
        "postgres_database": database_name if backend == "postgres" else None,
        "sqlite_database_file": Path(database_locator).name if backend == "sqlite" else None,
        "role": role,
        "policy_version": policy.version,
        "policy_sha256": policy_sha256,
        "planner": "ollama",
        "model": planner.model,
        "execution_budget": asdict(budget),
        "database_preflight": "passed",
        "cases": case_results,
        "summary": {
            "selected_cases": len(case_results),
            "sql_generation_successes": sum(row["sql_generation_success"] for row in case_results),
            "database_execution_successes": sum(
                row["execution_status"] == "succeeded" for row in case_results
            ),
            "result_correctness": "not_evaluated",
            "security_policy_compliant_cases": sum(
                row["security_policy_compliance"] == "compliant" for row in case_results
            ),
        },
        "limitations": [
            "Gold SQL was referenced but never sent to the planner or executed.",
            "Result correctness was not evaluated.",
            "Execution success does not imply semantic correctness.",
            (
                "SQLite has no PostgreSQL-style role grants; OS file permissions are a separate security boundary."
                if backend == "sqlite"
                else "PostgreSQL runtime privileges were preflighted against the selected role policy."
            ),
        ],
    }
    artifact_path = run_directory / "pilot.json"
    try:
        file_descriptor = os.open(
            artifact_path,
            os.O_WRONLY | os.O_CREAT | os.O_EXCL,
            0o600,
        )
        with os.fdopen(file_descriptor, "w", encoding="utf-8") as handle:
            json.dump(artifact, handle, ensure_ascii=False, indent=2, default=str)
            handle.write("\n")
    except OSError:
        raise PilotInputError(
            "Could not write pilot artifacts to the private output directory."
        ) from None
    return artifact_path


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--audit-report", type=Path, required=True)
    parser.add_argument(
        "--dataset-file",
        type=Path,
        action="append",
        required=True,
        help="Exact local source file from the audit (repeat for multiple files).",
    )
    parser.add_argument(
        "--reviewed-ids",
        required=True,
        help="Comma-separated 3-5 case IDs manually reviewed against schema and Gold SQL.",
    )
    parser.add_argument(
        "--policy", type=Path, required=True, help="Local SQLGuard role policy JSON."
    )
    parser.add_argument("--role", required=True, choices=sorted(_RUNTIME_LOGINS))
    parser.add_argument(
        "--database-name",
        required=True,
        help="Logical name for the audited BIRD database (not a connection string or path).",
    )
    args = parser.parse_args(argv)
    reviewed_ids = [value.strip() for value in args.reviewed_ids.split(",") if value.strip()]
    try:
        audit, cases = load_reviewed_cases(args.audit_report, args.dataset_file, reviewed_ids)
        policy, policy_sha256 = load_role_policy(args.policy, args.role)
        output = run_pilot(
            audit,
            cases,
            role=args.role,
            policy=policy,
            policy_sha256=policy_sha256,
            env=os.environ,
            database_name=args.database_name,
        )
    except PilotInputError as error:
        parser.error(str(error))
    print(f"pilot_run_id: {output.parent.name}")
    print(f"artifact: {output}")
    print(f"selected_cases: {len(cases)}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
