import json
from pathlib import Path

import pytest
import sqlglot

from sqlguard.security.audit import InMemoryAuditSink
from sqlguard.security.gate import (
    DecisionKind,
    GateMode,
    PolicySQLGate,
    SecurityContext,
)
from sqlguard.security.policy import load_default_policy
from sqlguard.security.violations import VIOLATIONS

CORPUS = json.loads((Path(__file__).parent / "attack_corpus.json").read_text(encoding="utf-8"))
POLICY = load_default_policy()


def gate_for(role="sales", **kwargs):
    return PolicySQLGate(SecurityContext(role=role), POLICY, **kwargs)


@pytest.mark.parametrize("case", CORPUS["cases"], ids=lambda case: case["id"])
def test_attack_corpus(case):
    gate = gate_for(case["role"], mode=GateMode(case.get("mode", "column_level")))
    decision = gate.check(case["sql"])

    assert decision.kind == DecisionKind(case["expect"]), decision
    assert decision.allowed == (case["expect"] in {"allow", "allow_partial"})
    if "violation" in case:
        assert decision.violations[0] == case["violation"], decision.violations
    else:
        assert decision.violations == ()
    if "removed" in case:
        assert list(decision.removed_columns) == case["removed"]
    if "notices" in case:
        assert list(decision.notices) == case["notices"]
    if "normalized" in case:
        assert decision.normalized_sql == case["normalized"]


def test_corpus_size_and_violation_codes_are_catalogued():
    cases = CORPUS["cases"]
    assert len(cases) >= 40
    assert len({case["id"] for case in cases}) == len(cases)
    assert {case["violation"] for case in cases if "violation" in case} <= set(VIOLATIONS)


@pytest.mark.parametrize(
    "case",
    [c for c in CORPUS["cases"] if c["expect"] in {"allow", "allow_partial"}],
    ids=lambda case: case["id"],
)
def test_allowed_sql_is_regenerated_bounded_and_free_of_forbidden_columns(case):
    mode = GateMode(case.get("mode", "column_level"))
    decision = gate_for(case["role"], mode=mode).check(case["sql"])
    if mode is GateMode.OFF:
        return
    tree = sqlglot.parse_one(decision.normalized_sql, read="postgres")
    limit = tree.args["limit"].expression
    assert int(limit.this) <= POLICY.limits.max_rows
    assert "/*" not in decision.normalized_sql and "--" not in decision.normalized_sql
    if mode is GateMode.COLUMN_LEVEL:
        forbidden = POLICY.forbidden_column_names(case["role"])
        referenced = {column.name.casefold() for column in tree.find_all(sqlglot.exp.Column)}
        assert not referenced & forbidden


def test_partial_answer_keeps_filters_and_reports_removed_columns():
    decision = gate_for("sales").check(
        "SELECT c.full_name, c.identity_number, c.city FROM customers c "
        "WHERE c.city = 'HCM' ORDER BY c.full_name LIMIT 5"
    )

    assert decision.kind is DecisionKind.ALLOW_PARTIAL
    assert decision.removed_columns == ("customers.identity_number",)
    assert decision.normalized_sql == (
        "SELECT c.full_name, c.city FROM customers AS c WHERE c.city = 'HCM' "
        "ORDER BY c.full_name LIMIT 5"
    )
    assert "Query narrowed" in decision.reason


def test_auto_partial_can_be_disabled_for_agent_driven_narrowing():
    decision = gate_for("sales", auto_partial=False).check(
        "SELECT full_name, identity_number FROM customers"
    )

    assert decision.kind is DecisionKind.DENY
    assert decision.violations == ("column_forbidden",)
    assert not decision.repairable


def test_denial_reason_does_not_name_hidden_columns_or_tables():
    for sql in (
        "SELECT identity_number FROM customers",
        "SELECT full_name FROM customers WHERE identity_number = '1'",
        "SELECT bank_reference FROM payments",
    ):
        decision = gate_for("sales").check(sql)
        assert not decision.allowed
        lowered = decision.reason.casefold()
        assert "identity" not in lowered and "bank" not in lowered and "payments" not in lowered


def test_repairable_flag_separates_syntax_from_policy_denials():
    assert gate_for().check("SELECT salary FROM customers").repairable
    assert gate_for().check("SELECT * FROM orders").repairable
    assert gate_for().check("SELECT FROM WHERE").repairable
    assert not gate_for().check("SELECT identity_number FROM customers").repairable
    assert not gate_for().check("SELECT pg_sleep(1)").repairable
    # A terminal finding is never hidden behind a repairable one.
    mixed = gate_for().check("SELECT * FROM pg_catalog.pg_user")
    assert mixed.violations[0] == "system_catalog"
    assert not mixed.repairable


def test_hashes_bind_input_and_executed_sql():
    gate = gate_for()
    first = gate.check("select order_id from orders")
    second = gate.check("SELECT   order_id FROM orders")

    assert first.input_hash != second.input_hash
    assert first.query_hash == second.query_hash
    assert len(first.query_hash) == 64


def test_gate_internal_error_fails_closed(monkeypatch):
    from sqlguard.security import gate as gate_module

    def boom(self, root):
        raise RuntimeError("private details")

    monkeypatch.setattr(gate_module._Evaluation, "_check_structure", boom)
    decision = gate_for().check("SELECT order_id FROM orders")

    assert not decision.allowed
    assert decision.violations == ("gate_error",)
    assert "private" not in decision.reason


def test_gate_records_every_decision_in_audit_without_sql_text():
    audit = InMemoryAuditSink()
    context = SecurityContext(role="sales", user_id="sales-demo", run_id="run-1")
    gate = PolicySQLGate(context, POLICY, audit=audit)

    gate.check("SELECT full_name, identity_number FROM customers")
    gate.check("SELECT identity_number FROM customers")

    first, second = audit.records
    assert (first.attempt, second.attempt) == (1, 2)
    assert first.outcome == "allowed" and first.decision_kind == "allow_partial"
    assert first.removed_columns == ("customers.identity_number",)
    assert second.outcome == "denied" and second.violations == ("column_forbidden",)
    assert {r.run_id for r in audit.records} == {"run-1"}
    assert all("SELECT" not in record.to_json() for record in audit.records)


def test_audit_failure_denies_the_query():
    class BrokenAudit:
        def record(self, record):
            raise OSError("disk full")

    decision = PolicySQLGate(SecurityContext("sales"), POLICY, audit=BrokenAudit()).check(
        "SELECT order_id FROM orders"
    )

    assert not decision.allowed
    assert decision.violations == ("gate_error",)


def test_off_mode_is_never_the_default():
    assert gate_for().mode is GateMode.COLUMN_LEVEL
    assert gate_for().check("DELETE FROM orders").violations == ("write_operation",)
