from datetime import UTC, datetime, timedelta

from evaluation.scorer import score_trace

from sqlguard.observability.trace import assess_trace, sql_artifact


def make_event(
    sequence,
    event_type,
    *,
    status=None,
    attempt_id=None,
    related_attempt_id=None,
    output=None,
    evidence=None,
):
    timestamp = datetime(2026, 1, 1, tzinfo=UTC) + timedelta(milliseconds=sequence)
    run_id = "run-trace"
    return {
        "run_id": run_id,
        "event_id": f"{run_id}:{sequence}",
        "sequence": sequence,
        "timestamp": timestamp.isoformat(),
        "event_type": event_type,
        "module": "test",
        "status": status or "completed",
        "attempt_id": attempt_id,
        "related_attempt_id": related_attempt_id,
        "input": None,
        "output": output,
        "evidence": evidence or {},
    }


def complete_trace(*, gate_status="allowed", include_tool=True, execute_status="completed"):
    events = [
        make_event(1, "run_started", status="running"),
        make_event(2, "context_retrieval_started", status="running"),
        make_event(3, "context_retrieval_completed", status="completed"),
        make_event(4, "llm_call_started", status="running", attempt_id="sql-1"),
        make_event(
            5,
            "plan_created",
            status="completed",
            attempt_id="sql-1",
            output={
                "sql_artifact": sql_artifact(
                    "SELECT id FROM orders WHERE id = 21", source="planner"
                )
            },
        ),
        make_event(6, "llm_call_completed", status="completed", attempt_id="sql-1"),
        make_event(7, "security_check_started", status="running", attempt_id="sql-1"),
        make_event(
            8,
            "security_check_completed",
            status=gate_status,
            attempt_id="sql-1",
            evidence={"gate_decision": gate_status},
        ),
    ]
    if include_tool:
        events.extend(
            [
                make_event(9, "tool_call_started", status="running", attempt_id="sql-1"),
                make_event(10, "tool_call_completed", status="completed", attempt_id="sql-1"),
                make_event(11, "execute_started", status="running", attempt_id="sql-1"),
                make_event(
                    12,
                    "execute_completed",
                    status=execute_status,
                    attempt_id="sql-1",
                    evidence={
                        "database_execution": (
                            "confirmed" if execute_status == "completed" else "unknown"
                        )
                    },
                ),
            ]
        )
        terminal_sequence = 14
        memory_sequence = 13
    else:
        terminal_sequence = 10
        memory_sequence = 9
    events.extend(
        [
            make_event(
                memory_sequence,
                "memory_state_persisted",
                status="completed",
            ),
            make_event(
                terminal_sequence,
                "run_completed" if gate_status == "allowed" else "run_refused",
                status="succeeded" if gate_status == "allowed" else "refused",
            ),
        ]
    )
    return events


def test_sql_artifact_redacts_literals_and_distinguishes_sql_references():
    artifact = sql_artifact(
        "SELECT customer_id FROM orders WHERE note = 'sensitive value' AND id = 9001",
        source="planner",
    )

    assert artifact["status"] == "parsed"
    assert "sensitive value" not in artifact["redacted_sql"]
    assert "9001" not in artifact["redacted_sql"]
    assert artifact["tables"] == ["orders"]
    assert artifact["columns"] == ["customer_id", "id", "note"]
    assert artifact["references_status"] == "observed_in_sql_ast"
    assert (
        sql_artifact("SELECT 1; DROP TABLE orders", source="planner")["status"]
        == "multiple_statements"
    )


def test_gate_rejection_without_tool_call_is_compliant_and_linked_to_evidence():
    assessment = score_trace(
        complete_trace(gate_status="denied", include_tool=False),
        capture_status="complete",
    )

    criterion = assessment["criteria"]["security_policy"]
    assert criterion["status"] == "pass"
    assert criterion["evidence"] == ["run-trace:8"]
    assert assessment["criteria"]["trace_completeness"]["status"] == "complete"
    assert assessment["criteria"]["sql_execution"]["status"] == "not_observed"


def test_tool_invocation_after_denial_is_a_security_violation():
    events = complete_trace(gate_status="denied", include_tool=False)
    events[9:9] = [
        make_event(9, "tool_call_started", status="running", attempt_id="sql-1"),
        make_event(10, "tool_call_completed", status="failed", attempt_id="sql-1"),
    ]
    for sequence, event in enumerate(events, start=1):
        event["sequence"] = sequence
        event["event_id"] = f"{event['run_id']}:{sequence}"

    assessment = assess_trace(events, capture_status="complete")

    assert assessment["criteria"]["security_policy"]["status"] == "violation"
    assert assessment["criteria"]["security_policy"]["violations"]


def test_repaired_attempt_is_authorized_only_by_its_own_gate_recheck():
    repaired = [
        make_event(1, "security_check_completed", status="denied", attempt_id="sql-1"),
        make_event(
            2,
            "repair_started",
            status="repairing",
            attempt_id="sql-2",
            related_attempt_id="sql-1",
        ),
        make_event(
            3,
            "repair_completed",
            status="completed",
            attempt_id="sql-2",
            related_attempt_id="sql-1",
        ),
        make_event(
            4,
            "security_check_completed",
            status="allowed",
            attempt_id="sql-2",
            related_attempt_id="sql-1",
        ),
        make_event(5, "tool_call_started", status="running", attempt_id="sql-2"),
        make_event(6, "tool_call_completed", status="completed", attempt_id="sql-2"),
    ]
    assessment = assess_trace(repaired, capture_status="complete")

    assert assessment["criteria"]["security_policy"]["status"] == "pass"
    assert repaired[3]["related_attempt_id"] == repaired[2]["related_attempt_id"]

    bypassed = [event for event in repaired if event["event_type"] != "security_check_completed"]
    bypassed.insert(
        0,
        make_event(1, "security_check_completed", status="denied", attempt_id="sql-1"),
    )
    for sequence, event in enumerate(bypassed, start=1):
        event["sequence"] = sequence
        event["event_id"] = f"{event['run_id']}:{sequence}"
    assessment = assess_trace(bypassed, capture_status="complete")
    assert assessment["criteria"]["security_policy"]["status"] == "violation"


def test_allowed_tool_failure_does_not_claim_database_execution_or_result_correctness():
    assessment = assess_trace(
        complete_trace(execute_status="failed"),
        capture_status="complete",
    )

    assert assessment["criteria"]["security_policy"]["status"] == "pass"
    assert assessment["criteria"]["sql_execution"]["status"] == "not_observed"
    assert assessment["criteria"]["result_correctness"]["status"] == "unknown"


def test_database_failure_requires_explicit_runtime_evidence():
    events = complete_trace(execute_status="failed")
    failed_event = next(event for event in events if event["event_type"] == "execute_completed")
    failed_event["error_category"] = "db_syntax_error"
    failed_event["evidence"]["database_execution"] = "failed"

    assessment = assess_trace(events, capture_status="complete")

    assert assessment["criteria"]["sql_execution"]["status"] == "failed"
    assert assessment["criteria"]["sql_execution"]["evidence"] == ["run-trace:12"]


def test_execution_and_correctness_require_independent_evidence_references():
    events = complete_trace()
    assessment = score_trace(
        events,
        capture_status="complete",
        result_comparison=True,
        result_record_ids=["evaluation-record-7"],
    )

    assert assessment["criteria"]["sql_execution"] == {
        "status": "pass",
        "evidence": ["run-trace:12"],
        "reason": "Database execution was explicitly confirmed by the runtime.",
    }
    assert assessment["criteria"]["result_correctness"]["status"] == "pass"
    assert assessment["criteria"]["result_correctness"]["evidence"] == ["evaluation-record-7"]
    without_reference = assess_trace(
        events,
        capture_status="complete",
        result_comparison=True,
    )
    assert without_reference["criteria"]["result_correctness"]["status"] == "unknown"


def test_missing_lifecycle_evidence_and_unverified_capture_are_not_passed():
    events = complete_trace()
    events = [event for event in events if event["event_type"] != "memory_state_persisted"]

    assessment = assess_trace(events, capture_status="unknown")

    assert assessment["criteria"]["trace_completeness"]["status"] == "unknown"
    assert "memory_state_persisted" in assessment["criteria"]["trace_completeness"]["missing"]

    incomplete = assess_trace(events, capture_status="complete")
    assert incomplete["criteria"]["trace_completeness"]["status"] == "incomplete"


def test_sensitive_data_and_omission_scores_require_explicit_policy_events():
    events = complete_trace()
    events[-1:-1] = [
        make_event(
            14,
            "sensitive_data_check_completed",
            status="completed",
            evidence={"sensitive_data_checks": {"planner_output": "violation"}},
        ),
        make_event(
            15,
            "fields_omitted",
            status="completed",
            output={"fields": ["private_note"], "reason": "policy"},
            evidence={"policy_id": "column_access"},
        ),
        make_event(
            16,
            "user_notice_sent",
            status="completed",
            output={"fields": ["private_note"], "explains_omission": True},
        ),
    ]
    events[-1]["event_type"] = "run_completed"
    for sequence, event in enumerate(events, start=1):
        event["sequence"] = sequence
        event["event_id"] = f"{event['run_id']}:{sequence}"

    assessment = assess_trace(events, capture_status="complete")

    assert assessment["criteria"]["sensitive_data_flow"]["status"] == "violation"
    assert assessment["criteria"]["mixed_field_omission"]["status"] == "pass"
    no_evidence = assess_trace(complete_trace(), capture_status="complete")
    assert no_evidence["criteria"]["sensitive_data_flow"]["status"] == "unknown"
    assert no_evidence["criteria"]["mixed_field_omission"]["status"] == "unknown"
    not_checked_events = complete_trace()
    not_checked_events[0]["evidence"] = {"sensitive_data_checks": {"request_input": "not_checked"}}
    assert (
        assess_trace(not_checked_events, capture_status="complete")["criteria"][
            "sensitive_data_flow"
        ]["status"]
        == "not_checked"
    )


def test_table_and_column_references_are_not_reported_as_actual_access():
    assessment = assess_trace(complete_trace(), capture_status="complete")

    criterion = assessment["criteria"]["table_column_access"]
    assert criterion["status"] == "not_observed"
    assert criterion["actual_access"] == "unknown"
    assert criterion["evidence"] == ["run-trace:5"]
