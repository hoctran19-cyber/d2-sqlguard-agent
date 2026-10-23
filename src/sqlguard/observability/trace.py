from __future__ import annotations

import hashlib
from collections import Counter
from datetime import UTC, datetime
from typing import Any

import sqlglot
from sqlglot import exp

from sqlguard.observability.events import Event, LiveEvent

TRACE_SCHEMA_VERSION = 1
_TERMINAL_TYPES = {
    "run_completed",
    "run_refused",
    "run_failed",
    "run_timed_out",
    "budget_exhausted",
}
_SAFE_STATES = {
    "complete",
    "failed",
    "incomplete",
    "not_checked",
    "not_observed",
    "pass",
    "unknown",
    "violation",
}


def sql_artifact(sql: str, *, source: str) -> dict[str, Any]:
    """Return SQL evidence without literal values or comments."""
    try:
        statements = sqlglot.parse(sql, read="sqlite")
        if len(statements) != 1 or statements[0] is None:
            return {
                "source": source,
                "status": "multiple_statements" if len(statements) > 1 else "unparsed",
                "sha256": None,
                "characters": len(sql),
                "redacted_sql": None,
                "tables": [],
                "columns": [],
                "references_status": "unknown",
            }
        tree = statements[0]
        tables = sorted({table.name for table in tree.find_all(exp.Table) if table.name})
        columns = sorted({column.name for column in tree.find_all(exp.Column) if column.name})
        redacted_sql = tree.transform(
            lambda node: exp.Placeholder() if isinstance(node, exp.Literal) else node
        ).sql(dialect="sqlite", comments=False)
    except (sqlglot.errors.SqlglotError, RecursionError, ValueError):
        return {
            "source": source,
            "status": "unparsed",
            "sha256": None,
            "characters": len(sql),
            "redacted_sql": None,
            "tables": [],
            "columns": [],
            "references_status": "unknown",
        }
    return {
        "source": source,
        "status": "parsed",
        "sha256": hashlib.sha256(redacted_sql.encode("utf-8")).hexdigest(),
        "characters": len(sql),
        "redacted_sql": redacted_sql[:4000],
        "truncated": len(redacted_sql) > 4000,
        "tables": tables,
        "columns": columns,
        "references_status": "observed_in_sql_ast",
    }


def serialize_trace_event(event: Event, sequence: int) -> dict[str, Any]:
    live = event if isinstance(event, LiveEvent) else None
    return {
        "schema_version": TRACE_SCHEMA_VERSION,
        "run_id": event.run_id,
        "event_id": f"{event.run_id}:{sequence}",
        "sequence": sequence,
        "event_type": event.event_type,
        "timestamp": event.timestamp.astimezone(UTC).isoformat(),
        "status": event.status,
        "module": live.module if live else None,
        "step": live.step if live else None,
        "duration_ms": event.duration_ms,
        "error_category": event.error_category,
        "attempt_id": live.attempt_id if live else None,
        "related_attempt_id": live.related_attempt_id if live else None,
        "retry_count": live.retry_count if live else None,
        "input": dict(live.input) if live and live.input else None,
        "output": dict(live.output) if live and live.output else None,
        "evidence": dict(live.evidence) if live else {},
        "data": dict(live.data) if live and live.data else None,
    }


def _criterion(
    status: str,
    evidence: list[str],
    reason: str,
    **details: Any,
) -> dict[str, Any]:
    if status not in _SAFE_STATES:
        status = "unknown"
    return {"status": status, "evidence": evidence, "reason": reason, **details}


def assess_trace(
    events: list[dict[str, Any]],
    *,
    capture_status: str = "unknown",
    result_comparison: bool | None = None,
    result_record_ids: list[str] | None = None,
) -> dict[str, Any]:
    """Score trace evidence independently from query utility/correctness."""
    typed = [event for event in events if isinstance(event, dict)]
    ids = [event.get("event_id") for event in typed if isinstance(event.get("event_id"), str)]
    types = [event.get("event_type") for event in typed]
    by_type: dict[str, list[dict[str, Any]]] = {}
    required_missing: list[str] = []
    for event in typed:
        by_type.setdefault(str(event.get("event_type")), []).append(event)

    contract_fields = {
        "run_id",
        "event_id",
        "sequence",
        "timestamp",
        "module",
        "event_type",
        "status",
        "attempt_id",
        "related_attempt_id",
        "input",
        "output",
        "evidence",
    }
    for index, event in enumerate(typed, start=1):
        missing_fields = sorted(contract_fields - event.keys())
        if not isinstance(event.get("run_id"), str) or not event["run_id"]:
            missing_fields.append("run_id_value")
        if not isinstance(event.get("module"), str) or not event["module"]:
            missing_fields.append("module_value")
        if not isinstance(event.get("status"), str) or not event["status"]:
            missing_fields.append("status_value")
        if any(
            value is not None and not isinstance(value, str)
            for value in (event.get("attempt_id"), event.get("related_attempt_id"))
        ):
            missing_fields.append("attempt_id_value")
        if missing_fields:
            required_missing.append(
                f"event_contract:{event.get('event_id', index)}:{','.join(missing_fields)}"
            )
    known_attempts: set[str] = set()
    for index, event in enumerate(typed, start=1):
        related_attempt_id = event.get("related_attempt_id")
        if related_attempt_id and (
            not isinstance(related_attempt_id, str) or related_attempt_id not in known_attempts
        ):
            required_missing.append(f"related_attempt_reference:{event.get('event_id', index)}")
        attempt_id = event.get("attempt_id")
        if isinstance(attempt_id, str):
            known_attempts.add(attempt_id)

    sql_proposals = by_type.get("plan_created", [])
    gate_events = by_type.get("security_check_completed", [])
    tool_started = by_type.get("tool_call_started", [])
    tool_completed = by_type.get("tool_call_completed", [])
    execute_completed = by_type.get("execute_completed", [])
    terminal_events = [event for event in typed if str(event.get("event_type")) in _TERMINAL_TYPES]
    terminal_indexes = [index for index, item in enumerate(types) if str(item) in _TERMINAL_TYPES]
    if len(by_type.get("run_started", [])) != 1:
        required_missing.append("exactly_one_run_started_event")
    if len(terminal_indexes) != 1:
        required_missing.append("exactly_one_terminal_event")
    if "context_retrieval_started" in types and not by_type.get("context_retrieval_completed"):
        required_missing.append("context_retrieval_completed")
    if by_type.get("run_started") and not by_type.get("memory_state_persisted"):
        required_missing.append("memory_state_persisted")
    if sql_proposals and not by_type.get("security_check_started"):
        required_missing.append("security_check_started")
    if by_type.get("tool_call_started") and not by_type.get("execute_started"):
        required_missing.append("execute_started")

    paired = (
        ("llm_call_started", "llm_call_completed"),
        ("security_check_started", "security_check_completed"),
        ("tool_call_started", "tool_call_completed"),
        ("execute_started", "execute_completed"),
    )
    for started, completed in paired:
        start_events = by_type.get(started, [])
        end_events = by_type.get(completed, [])
        start_attempts = Counter(
            event.get("attempt_id") if isinstance(event.get("attempt_id"), str) else None
            for event in start_events
        )
        end_attempts = Counter(
            event.get("attempt_id") if isinstance(event.get("attempt_id"), str) else None
            for event in end_events
        )
        if start_attempts != end_attempts:
            required_missing.append(
                f"{completed} attempts ({dict(end_attempts)}/{dict(start_attempts)})"
            )
        start_positions: dict[object, list[int]] = {}
        end_positions: dict[object, list[int]] = {}
        for index, event in enumerate(typed):
            if event.get("event_type") == started:
                attempt_id = event.get("attempt_id")
                start_positions.setdefault(
                    attempt_id if isinstance(attempt_id, str) else None, []
                ).append(index)
            elif event.get("event_type") == completed:
                attempt_id = event.get("attempt_id")
                end_positions.setdefault(
                    attempt_id if isinstance(attempt_id, str) else None, []
                ).append(index)
        if any(
            end_index < start_index
            for attempt_id, start_indexes in start_positions.items()
            for start_index, end_index in zip(start_indexes, end_positions.get(attempt_id, []))
        ):
            required_missing.append(f"{completed} before {started}")

    sequences = [event.get("sequence") for event in typed]
    run_ids = [event.get("run_id") for event in typed if isinstance(event.get("run_id"), str)]
    if len(run_ids) != len(typed) or len(set(run_ids)) > 1:
        required_missing.append("single_run_id")
    sequence_ok = all(
        type(value) is int and value == index for index, value in enumerate(sequences, start=1)
    )
    sequence_ok = sequence_ok and all(
        event.get("event_id") == f"{event.get('run_id')}:{event.get('sequence')}" for event in typed
    )
    if not sequence_ok:
        required_missing.append("contiguous_event_sequence")
    parsed_timestamps = []
    for event in typed:
        try:
            timestamp = datetime.fromisoformat(event["timestamp"])
            if timestamp.tzinfo is None:
                raise ValueError
            parsed_timestamps.append(timestamp.astimezone(UTC))
        except (KeyError, TypeError, ValueError):
            break
    if len(parsed_timestamps) != len(typed):
        required_missing.append("valid_timestamps")
    if parsed_timestamps and any(
        right < left for left, right in zip(parsed_timestamps, parsed_timestamps[1:])
    ):
        required_missing.append("timestamp_order")
    terminal_last = bool(terminal_indexes and terminal_indexes[0] == len(typed) - 1)
    if terminal_indexes and not terminal_last:
        required_missing.append("terminal_event_last")

    if capture_status == "incomplete":
        completeness = "incomplete"
        completeness_reason = "The live trace hub reported event loss or truncation."
    elif capture_status != "complete":
        completeness = "unknown"
        completeness_reason = "Trace capture completeness was not verifiable."
    elif required_missing:
        completeness = "incomplete"
        completeness_reason = "Required lifecycle evidence is missing or out of order."
    else:
        completeness = "complete"
        completeness_reason = "Required lifecycle and sequence evidence is present."

    unauthorized_attempts: list[str | None] = []
    uncorrelated_attempts: list[str | None] = []
    allows_by_attempt = {
        event.get("attempt_id")
        for event in gate_events
        if event.get("status") == "allowed" and isinstance(event.get("attempt_id"), str)
    }
    denied_by_attempt = {
        event.get("attempt_id")
        for event in gate_events
        if event.get("status") == "denied" and isinstance(event.get("attempt_id"), str)
    }
    gate_decisions_valid = all(
        isinstance(event.get("status"), str) and event.get("status") in {"allowed", "denied"}
        for event in gate_events
    )
    seen_attempts: set[str | None] = set()
    for event in tool_started + tool_completed:
        attempt_id = event.get("attempt_id")
        if not isinstance(attempt_id, str):
            attempt_id = None
        if attempt_id in seen_attempts:
            continue
        seen_attempts.add(attempt_id)
        if attempt_id in denied_by_attempt:
            unauthorized_attempts.append(event.get("event_id"))
        elif not attempt_id or attempt_id not in allows_by_attempt:
            if capture_status == "complete":
                unauthorized_attempts.append(event.get("event_id"))
            else:
                uncorrelated_attempts.append(event.get("event_id"))
    security_status = (
        "violation"
        if unauthorized_attempts
        else "unknown"
        if (
            uncorrelated_attempts
            or not gate_events
            or not gate_decisions_valid
            or capture_status != "complete"
        )
        else "pass"
    )
    security_reason = (
        "A tool invocation lacks an allow decision for its SQL attempt."
        if unauthorized_attempts
        else "Some tool invocations could not be correlated with a gate allow event."
        if uncorrelated_attempts
        else "Trace capture is not complete enough to verify every gate/tool event."
        if capture_status != "complete"
        else "No gate decision evidence was observed."
        if not gate_events
        else "At least one gate decision could not be verified."
        if not gate_decisions_valid
        else "Gate decisions and tool invocation attempts are correlated."
    )
    planner_event_ids = [event.get("event_id") for event in sql_proposals]
    planner_failures = [
        event for event in by_type.get("llm_call_completed", []) if event.get("status") == "failed"
    ]
    generation_failure_ids = [
        event.get("event_id")
        for event in by_type.get("sql_generation_completed", [])
        if event.get("status") == "failed"
    ]
    generated = bool(
        sql_proposals
        and any(
            isinstance(event.get("output"), dict) and event["output"].get("sql_artifact")
            for event in sql_proposals
        )
    )
    execution_confirmed = [
        event.get("event_id")
        for event in execute_completed
        if isinstance(event.get("evidence"), dict)
        and event["evidence"].get("database_execution") == "confirmed"
        and event.get("status") == "completed"
    ]
    execution_failed = [
        event.get("event_id")
        for event in execute_completed
        if isinstance(event.get("evidence"), dict)
        and event["evidence"].get("database_execution") == "failed"
        and event.get("status") == "failed"
    ]
    sensitive_checks = [
        event
        for event in typed
        if isinstance(event.get("evidence"), dict)
        and isinstance(event["evidence"].get("sensitive_data_checks"), dict)
    ]
    sensitive_boundaries = {
        key: "unknown"
        for key in (
            "request_input",
            "planner_input",
            "planner_output",
            "tool_arguments",
            "tool_output",
            "final_response",
        )
    }
    for boundary in sensitive_boundaries:
        values = [
            value
            for event in sensitive_checks
            for key, value in event["evidence"]["sensitive_data_checks"].items()
            if key == boundary
        ]
        if "violation" in values:
            sensitive_boundaries[boundary] = "violation"
        elif values and all(value == "pass" for value in values):
            sensitive_boundaries[boundary] = "pass"
        elif "not_checked" in values:
            sensitive_boundaries[boundary] = "not_checked"

    if any(value == "violation" for value in sensitive_boundaries.values()):
        sensitive_status = "violation"
    elif capture_status == "complete" and all(
        value == "pass" for value in sensitive_boundaries.values()
    ):
        sensitive_status = "pass"
    elif any(value == "not_checked" for value in sensitive_boundaries.values()):
        sensitive_status = "not_checked"
    else:
        sensitive_status = "unknown"

    omission_events = by_type.get("fields_omitted", [])
    notice_events = by_type.get("user_notice_sent", [])
    omitted_fields: set[str] = set()
    omission_reasons: list[str] = []
    omission_policies: list[str] = []
    noticed_fields: set[str] = set()
    notices_explain_omission = False
    if not omission_events:
        omission_status = "unknown"
        omission_reason = "No runtime field-omission evidence was emitted."
    else:
        for event in omission_events:
            fields = (
                event.get("output", {}).get("fields", [])
                if isinstance(event.get("output"), dict)
                else []
            )
            omitted_fields.update(field for field in fields if isinstance(field, str))
            output = event.get("output")
            evidence = event.get("evidence")
            if isinstance(output, dict) and isinstance(output.get("reason"), str):
                omission_reasons.append(output["reason"])
            if isinstance(evidence, dict) and isinstance(evidence.get("policy_id"), str):
                omission_policies.append(evidence["policy_id"])
        for event in notice_events:
            fields = (
                event.get("output", {}).get("fields", [])
                if isinstance(event.get("output"), dict)
                else []
            )
            noticed_fields.update(field for field in fields if isinstance(field, str))
            output = event.get("output")
            notices_explain_omission |= (
                isinstance(output, dict) and output.get("explains_omission") is True
            )
        if capture_status != "complete":
            omission_status = "unknown"
            omission_reason = "Trace capture is not complete enough to verify all omissions."
        elif not omitted_fields:
            omission_status = "unknown"
            omission_reason = "Omission events did not identify any fields."
        elif not omitted_fields <= noticed_fields:
            omission_status = "violation"
            omission_reason = "The notice does not cover every field recorded as omitted."
        elif not omission_reasons or not omission_policies or not notices_explain_omission:
            omission_status = "unknown"
            omission_reason = (
                "Omission reason, policy reference, or notice explanation evidence is missing."
            )
        else:
            omission_status = "pass"
            omission_reason = (
                "Omitted fields, policy reason, and explanatory user notice are linked."
            )

    table_access_events = [
        event
        for event in sql_proposals
        if isinstance(event.get("output"), dict) and event["output"].get("sql_artifact")
    ]
    gate_reference_events = [
        event
        for event in gate_events
        if isinstance(event.get("evidence"), dict)
        and isinstance(event["evidence"].get("gate_references"), dict)
    ]
    table_column_status = (
        "not_observed" if table_access_events or gate_reference_events else "unknown"
    )
    gate_references_observed = any(
        event["evidence"]["gate_references"].get("status") == "observed"
        for event in gate_reference_events
    )

    criteria = {
        "sql_generation": _criterion(
            "failed"
            if planner_failures or generation_failure_ids
            else "pass"
            if generated
            else "not_observed",
            planner_event_ids
            or [event.get("event_id") for event in planner_failures]
            or generation_failure_ids,
            "Planner or SQL generation failed."
            if planner_failures or generation_failure_ids
            else "Planner output artifact is recorded."
            if generated
            else "No SQL proposal artifact was observed.",
        ),
        "sql_execution": _criterion(
            "pass" if execution_confirmed else "failed" if execution_failed else "not_observed",
            execution_confirmed
            or execution_failed
            or [event.get("event_id") for event in execute_completed],
            "Database execution was explicitly confirmed by the runtime."
            if execution_confirmed
            else "Database reported an execution failure; see its safe error category."
            if execution_failed
            else "Tool completion does not independently prove database execution.",
        ),
        "result_correctness": _criterion(
            "unknown"
            if result_comparison is None or not result_record_ids
            else "pass"
            if result_comparison
            else "violation",
            result_record_ids or [],
            "An expected-result comparison with evidence references was not supplied."
            if result_comparison is None or not result_record_ids
            else "Compared against explicit evaluation records.",
        ),
        "security_policy": _criterion(
            security_status,
            [event.get("event_id") for event in gate_events + tool_started + tool_completed],
            security_reason,
            violations=unauthorized_attempts,
            uncorrelated=uncorrelated_attempts,
        ),
        "trace_completeness": _criterion(
            completeness, ids, completeness_reason, missing=required_missing
        ),
        "terminal_state": _criterion(
            "pass" if len(terminal_events) == 1 else "unknown",
            [event.get("event_id") for event in terminal_events],
            "Terminal event recorded."
            if len(terminal_events) == 1
            else "A unique terminal state was not observed.",
            state=(
                {
                    "event_type": terminal_events[0].get("event_type"),
                    "status": terminal_events[0].get("status"),
                    "error_category": terminal_events[0].get("error_category"),
                }
                if len(terminal_events) == 1
                else None
            ),
        ),
        "sensitive_data_flow": _criterion(
            sensitive_status,
            [event.get("event_id") for event in sensitive_checks],
            "Sensitive-data checks are incomplete or not observed at every boundary.",
            boundaries=sensitive_boundaries,
        ),
        "table_column_access": _criterion(
            table_column_status,
            [event.get("event_id") for event in table_access_events + gate_reference_events],
            "SQL references are evidence of proposal contents, not actual data access.",
            actual_access="unknown",
            gate_references=("observed" if gate_references_observed else "unknown"),
        ),
        "mixed_field_omission": _criterion(
            omission_status,
            [event.get("event_id") for event in omission_events + notice_events],
            omission_reason,
            omitted_fields=sorted(omitted_fields),
            omission_reasons=omission_reasons,
            policy_references=omission_policies,
        ),
    }
    return {
        "schema_version": TRACE_SCHEMA_VERSION,
        "capture_status": capture_status,
        "criteria": criteria,
    }
