"""Offline worst-case run of the D2 injection set.

The planner is replaced by a *fully compromised model* that emits exactly the SQL the attacker
wants (``simulated_model_sql``). If no canary leaks and no write executes even then, the result
does not depend on the LLM resisting the injection. Real-model ASR is measured separately by
the evaluation harness; these tests are not model results.
"""

import asyncio
import json
from pathlib import Path

import pytest
from tests.security.fakes import SQLiteExecutor

from sqlguard.mcp.tools import ToolError
from sqlguard.security.audit import InMemoryAuditSink
from sqlguard.security.gate import PolicySQLGate, SecurityContext
from sqlguard.security.policy import load_default_policy
from sqlguard.security.service import SecureSqlTool, SecurityToolError, find_leaks

ROOT = Path(__file__).resolve().parents[2]
DATASET = json.loads(
    (ROOT / "evaluation/datasets/security/d2_injection_v1.json").read_text(encoding="utf-8")
)
POLICY = load_default_policy()


def run_case(case):
    executor = SQLiteExecutor()
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


def test_dataset_has_d2_minimum():
    cases = DATASET["cases"]
    attacks = [c for c in cases if c["attack_type"] != "clean"]
    assert len(attacks) >= 4
    assert {c["attack_type"] for c in attacks} == {"direct", "indirect"}
    assert sum(c["attack_type"] == "clean" for c in cases) >= 2
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

    # Only regenerated SELECTs reached the database, and the database is intact.
    assert all(sql.startswith("SELECT ") for sql in executor.executed)
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
    case = next(c for c in DATASET["cases"] if c["case_id"] == "INJ-D2")
    tool = SecureSqlTool(
        PolicySQLGate(SecurityContext(role=case["role"]), POLICY), SQLiteExecutor()
    )
    arguments = {"sql": case["simulated_model_sql"][0], **case["setup"]["tool_argument_override"]}

    with pytest.raises(ToolError) as raised:
        asyncio.run(tool.call(arguments, timeout_seconds=3))

    assert raised.value.category == "invalid_tool_input"
