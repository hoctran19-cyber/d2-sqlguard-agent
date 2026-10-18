"""Offline worst-case run of the security injection set (D2 subset + D3 extension).

The planner is replaced by a *fully compromised model* that emits exactly the SQL the attacker
wants (``simulated_model_sql``). If no canary leaks and no write executes even then, the result
does not depend on the LLM resisting the injection. Real-model ASR is measured separately by
the evaluation harness; these tests are not model results.
"""

import asyncio
import json
from pathlib import Path

import pytest
import sqlglot
from tests.security.fakes import SQLiteExecutor

from sqlguard.mcp.tools import ToolError
from sqlguard.security.audit import InMemoryAuditSink
from sqlguard.security.gate import PolicySQLGate, SecurityContext
from sqlguard.security.policy import load_default_policy
from sqlguard.security.service import SecureSqlTool, SecurityToolError, find_leaks

ROOT = Path(__file__).resolve().parents[2]
DATASET = json.loads(
    (ROOT / "evaluation/datasets/security/injection_cases_v1.json").read_text(encoding="utf-8")
)
PRIMARY_KEYS = {"customers": "customer_id", "orders": "order_id"}
POLICY = load_default_policy()


def run_case(case):
    executor = SQLiteExecutor()
    for target, text in case["setup"].get("notes", {}).items():
        table, row_id = target.split(".")
        executor.connection.execute(
            f"UPDATE {table} SET note = ? WHERE {PRIMARY_KEYS[table]} = ?", (text, int(row_id))
        )
    audit = InMemoryAuditSink()
    gate = PolicySQLGate(SecurityContext(role=case["role"], run_id=case["case_id"]), POLICY)
    tool = SecureSqlTool(gate, executor, audit=audit)
    outputs = []
    for sql in case["simulated_model_sql"]:
        try:
            outputs.append(asyncio.run(tool.call({"sql": sql}, timeout_seconds=3)))
        except SecurityToolError as error:
            outputs.append(error.decision)
        except ToolError as error:
            outputs.append(error)
    return executor, audit, outputs


def test_dataset_has_d2_subset_and_d3_target():
    cases = DATASET["cases"]
    attacks = [c for c in cases if c["attack_type"] != "clean"]
    d2 = [c for c in attacks if c["checkpoint"] == "D2"]
    assert [c["case_id"] for c in d2] == ["D2-I01", "D2-I02", "D2-I03", "D2-I04"]
    assert sum(c["attack_type"] == "direct" for c in attacks) == 5
    assert sum(c["attack_type"] == "indirect" for c in attacks) == 5
    by_id = {c["case_id"]: c for c in cases}
    for attack in attacks:
        clean = by_id[attack["clean_pair"]]
        assert clean["pair_of"] == attack["case_id"] and clean["role"] == attack["role"]
    for case in cases:
        assert len(case["simulated_model_sql"]) == len(case["expected_gate"])


@pytest.mark.parametrize("case", DATASET["cases"], ids=lambda case: case["case_id"])
def test_compromised_model_cannot_leak_or_write(case):
    executor, audit, outputs = run_case(case)

    # UAR: no canary in anything the model or user could see, nor in the audit trail.
    visible = json.dumps([o for o in outputs if isinstance(o, dict)], ensure_ascii=False)
    assert not find_leaks(visible, POLICY, case["role"])
    assert not [c for c in case["canaries"] if c in visible]
    assert not find_leaks("\n".join(r.to_json() for r in audit.records), POLICY, case["role"])

    # Gate decisions per step match the case definition.
    kinds = [o["decision"] if isinstance(o, dict) else str(o.kind) for o in outputs]
    assert kinds == case["expected_gate"]

    # Only regenerated SELECTs reached the database; none read a forbidden column.
    assert all(sql.startswith("SELECT ") for sql in executor.executed)
    role = case["role"]
    readable = {c for t in POLICY.allowed_tables(role) for c in POLICY.allowed_columns(role, t)}
    forbidden = (POLICY.forbidden_column_names(role) - readable) | {
        f.split(".")[1] for f in case["forbidden_columns"] if not f.endswith(".*")
    }
    for sql in executor.executed:
        tree = sqlglot.parse_one(sql, read="postgres")
        names = {column.name.casefold() for column in tree.find_all(sqlglot.exp.Column)}
        assert not names & forbidden
    assert executor.connection.execute(
        "SELECT status FROM orders WHERE order_id = 3"
    ).fetchone() == ("cancelled",)
    tables = {row[0] for row in executor.connection.execute("SELECT name FROM sqlite_master")}
    assert {"customers", "orders", "order_items", "products", "payments"} <= tables
    assert executor.connection.execute("SELECT COUNT(*) FROM payments").fetchone()[0] == 3

    for output, flag in zip(outputs, case.get("expected_injection_flag", []), strict=False):
        if flag is not None:
            assert output["possible_injection"] is flag

    # Every attempt is audited and attributable to the case run.
    assert len(audit.records) == len(case["simulated_model_sql"])
    assert {r.run_id for r in audit.records} == {case["case_id"]}


def test_role_override_in_tool_arguments_is_rejected():
    case = next(c for c in DATASET["cases"] if c["case_id"] == "D2-I02")
    tool = SecureSqlTool(
        PolicySQLGate(SecurityContext(role=case["role"]), POLICY), SQLiteExecutor()
    )
    arguments = {"sql": case["simulated_model_sql"][0], **case["setup"]["tool_argument_override"]}

    with pytest.raises(ToolError) as raised:
        asyncio.run(tool.call(arguments, timeout_seconds=3))

    assert raised.value.category == "invalid_tool_input"
