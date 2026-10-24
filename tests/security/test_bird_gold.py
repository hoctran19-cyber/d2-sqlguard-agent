"""BIRD Mini-Dev Financial gold SQL against the bird-financial-v1 policy.

Guards against false rejection on the benchmark itself: every non-subquery gold query must be
accepted for each role that may read its columns, and denied for every other role.
"""

import json
import re
from pathlib import Path

import pytest

from sqlguard.security.gate import PolicySQLGate, SecurityContext
from sqlguard.security.policy import load_policy

ROOT = Path(__file__).resolve().parents[2]
DATASET = json.loads(
    (ROOT / "evaluation/datasets/bird_financial/financial_questions_v1.json").read_text(
        encoding="utf-8"
    )
)
POLICY = load_policy("bird_financial_v1")
ROLES = ("teller", "credit", "risk")


def test_dataset_shape_matches_team_decision():
    questions = DATASET["questions"]
    assert len(questions) == 32
    assert sum(q["uses_subquery"] for q in questions) == 5
    usable = [q for q in questions if not q["uses_subquery"]]
    assert all("credit" in q["allowed_roles"] for q in usable)
    assert sum(len(q["allowed_roles"]) == 3 for q in usable) == 13


@pytest.mark.parametrize("question", DATASET["questions"], ids=lambda q: str(q["question_id"]))
def test_gold_sql_decision_per_role(question):
    for role in ROLES:
        decision = PolicySQLGate(SecurityContext(role), POLICY).check(question["gold_sql_postgres"])
        assert decision.allowed == (role in question["allowed_roles"]), (role, decision)
        if question["uses_subquery"]:
            assert "subquery_not_supported" in decision.violations
        elif not decision.allowed:
            # Denied only because the role lacks a column or table, never for syntax.
            assert decision.violations[0] in {
                "column_forbidden",
                "column_forbidden_narrowable",
                "table_not_allowed",
            }, decision


def test_bridge_table_join_on_two_foreign_keys_is_allowed():
    gate = PolicySQLGate(SecurityContext("teller"), POLICY)
    ok = gate.check(
        "SELECT c.gender, a.frequency FROM client AS c JOIN district AS d "
        "ON c.district_id = d.district_id JOIN account AS a ON a.district_id = d.district_id "
        "JOIN disp AS x ON c.client_id = x.client_id AND a.account_id = x.account_id"
    )
    not_fk = gate.check(
        "SELECT c.gender FROM client AS c JOIN disp AS x "
        "ON c.client_id = x.client_id AND x.type = 'OWNER'"
    )

    assert ok.allowed
    assert not not_fk.allowed and not_fk.violations == ("join_not_allowed",)


def test_overlay_and_forbidden_columns_per_role():
    def check(role, sql):
        return PolicySQLGate(SecurityContext(role), POLICY).check(sql)

    for role in ROLES:
        for sql in (
            "SELECT id_number FROM client",
            "SELECT address FROM client",
            "SELECT placeholder FROM card",
        ):
            assert check(role, sql).violations == ("column_forbidden",), (role, sql)
        assert check(role, "SELECT client_id, full_name FROM client").allowed
        assert check(role, "SELECT account_id, service_note FROM account").allowed
        assert check(role, 'SELECT order_id, note FROM "order"').allowed
        assert check(role, "SELECT note FROM trans").violations == ("column_unknown",)
    assert check("credit", "SELECT birth_date FROM client").allowed
    assert not check("risk", "SELECT birth_date FROM client").allowed
    assert check("teller", "SELECT amount FROM loan").violations == ("table_not_allowed",)
    assert check("risk", "SELECT bank, account FROM trans").allowed
    assert not check("credit", 'SELECT bank_to FROM "order"').allowed


def test_canaries_sit_in_columns_no_role_may_read():
    assert {(c.table, c.column) for c in POLICY.canaries} == {
        ("client", "id_number"),
        ("card", "placeholder"),
    }
    for role in ROLES:
        assert POLICY.canaries_for(role) == POLICY.canaries


def test_note_targets_use_the_synthetic_note_columns():
    assert POLICY.note_targets == {"account": "account_id", "order": "order_id"}
    assert POLICY.note_column("account") == "service_note"
    assert POLICY.note_column("order") == "note"


def test_postgres_grants_match_the_policy():
    """db/bird_financial/10_roles.sql must grant exactly the policy's columns per role."""
    sql = (ROOT / "db/bird_financial/10_roles.sql").read_text(encoding="utf-8")
    grants = {role: {} for role in ROLES}
    pattern = r'GRANT SELECT \(([^)]*)\)\s+ON "?(\w+)"? TO sqlguard_(\w+)_ro;'
    for columns, table, role in re.findall(pattern, sql):
        grants[role][table] = frozenset(c.strip() for c in columns.split(","))

    assert grants == {role: POLICY.roles[role] for role in ROLES}
