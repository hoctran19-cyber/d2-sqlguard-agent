"""Kiểm thử đầu-cuối: AgentController -> gate -> SecureSqlTool -> PostgresExecutor -> PostgreSQL.

Cần một server PostgreSQL dùng một lần (xem tests/security/test_db_grants.py), ví dụ:

    SQLGUARD_TEST_PG_ADMIN_DSN="host=localhost port=5432 user=postgres dbname=postgres" \
        pytest -m db tests/security/test_agent_postgres_e2e.py

Planner là planner giả tất định (không cần Ollama hay mạng). Fixture ``database`` được dùng lại
từ test_db_grants: mỗi module tự tạo và xóa một database riêng, nạp schema, role và dữ liệu mẫu.
"""

import asyncio

import pytest
from tests.security.test_db_grants import database  # noqa: F401
from tests.unit.test_agent_repair import ScriptedRepairPlanner

psycopg = pytest.importorskip("psycopg")
from psycopg import conninfo  # noqa: E402

from sqlguard.agent.controller import AgentController, RunScope  # noqa: E402
from sqlguard.agent.models import AgentRequest, ExecutionBudget, RunStatus  # noqa: E402
from sqlguard.agent.runtime import build_query_runtime_factory  # noqa: E402
from sqlguard.mcp.tools import InProcessToolRegistry, MockQueryTool  # noqa: E402
from sqlguard.memory.store import InMemoryMemory  # noqa: E402
from sqlguard.observability.events import InMemoryEventSink  # noqa: E402
from sqlguard.security.audit import InMemoryAuditSink  # noqa: E402
from sqlguard.security.gate import ReadOnlySQLGate  # noqa: E402

pytestmark = pytest.mark.db

ORDERS_SQL = "SELECT order_id, status FROM orders ORDER BY order_id LIMIT 3"


def make_env(role, dsn):
    return {"SQLGUARD_QUERY_SOURCE": "postgres", f"SQLGUARD_DB_DSN_{role.upper()}": dsn}


def make_controller(role, dsn, planner, audit, events=None, budget=None):
    # PostgresExecutor thật được dựng từ DSN theo role, giống đường chạy production.
    factory = build_query_runtime_factory(role, make_env(role, dsn), audit=audit)

    def scope(run_id):
        built = factory.for_run(run_id)
        return RunScope(built.gate, InProcessToolRegistry([built.tool]))

    return AgentController(
        planner=planner,
        # Tool/gate dùng chung bên dưới chỉ là mock; nếu bị dùng nhầm sẽ thấy "demo_value=1".
        tools=InProcessToolRegistry([MockQueryTool()]),
        security_gate=ReadOnlySQLGate(),
        memory=InMemoryMemory(),
        events=events or InMemoryEventSink(),
        budget=budget or ExecutionBudget(),
        run_scope_factory=scope,
    )


def run(controller):
    return asyncio.run(controller.run(AgentRequest("question")))


def count_orders(dsns):
    with psycopg.connect(dsns["admin"]) as conn:
        return conn.execute("SELECT count(*) FROM orders").fetchone()[0]


def test_legitimate_question_returns_real_database_rows(database):  # noqa: F811
    audit = InMemoryAuditSink()
    events = InMemoryEventSink()
    planner = ScriptedRepairPlanner(ORDERS_SQL, [ORDERS_SQL])
    result = run(make_controller("sales", database["sales"], planner, audit, events))

    assert result.succeeded
    assert "demo_value" not in result.state.final_answer
    with psycopg.connect(database["admin"]) as conn:
        expected = conn.execute("SELECT order_id, status FROM orders ORDER BY 1 LIMIT 3").fetchall()
    # Kết quả của SecureSqlTool là envelope không đáng tin chứa đúng các hàng trong database.
    assert "untrusted" in result.state.final_answer
    for order_id, status in expected:
        assert str(order_id) in result.state.final_answer and status in result.state.final_answer
    assert planner.feedback == [] and result.state.llm_call_count == 1

    # Audit và event khớp với run thật: gate (controller) + execute (tool), cùng run_id.
    assert {r.run_id for r in audit.records} == {result.state.run_id}
    assert [(r.phase, r.outcome) for r in audit.records] == [
        ("gate", "allowed"),
        ("execute", "executed"),
    ]
    assert audit.records[1].row_count == 3 and {r.role for r in audit.records} == {"sales"}
    assert {e.run_id for e in events.events} == {result.state.run_id}


def test_gate_rejected_query_never_reaches_database(database):  # noqa: F811
    before = count_orders(database)
    audit = InMemoryAuditSink()
    events = InMemoryEventSink()
    planner = ScriptedRepairPlanner("DELETE FROM orders", [ORDERS_SQL])
    result = run(make_controller("sales", database["sales"], planner, audit, events))

    assert result.state.status == RunStatus.REFUSED
    assert result.state.failure_reason == "security_rejection"
    # Không repair, không retry, không gọi tool; database không đổi.
    assert planner.feedback == [] and result.state.llm_call_count == 1
    assert result.state.tool_call_count == 0 and result.state.retry_count == 0
    assert count_orders(database) == before
    assert [(r.phase, r.outcome) for r in audit.records] == [("gate", "denied")]
    assert not any(e.event_type.startswith(("repair", "tool_call")) for e in events.events)


def test_forbidden_column_is_stopped_before_database(database):  # noqa: F811
    audit = InMemoryAuditSink()
    planner = ScriptedRepairPlanner(
        "SELECT full_name FROM customers ORDER BY phone_number", [ORDERS_SQL]
    )
    result = run(make_controller("sales", database["sales"], planner, audit))
    assert not result.succeeded
    assert result.state.tool_call_count == 0
    assert all(r.phase == "gate" for r in audit.records)


def test_repairable_denial_is_repaired_then_executed_on_real_database(database):  # noqa: F811
    audit = InMemoryAuditSink()
    events = InMemoryEventSink()
    planner = ScriptedRepairPlanner("SELECT no_such_column FROM orders", [ORDERS_SQL])
    result = run(make_controller("sales", database["sales"], planner, audit, events))

    assert result.succeeded and len(planner.feedback) == 1
    assert result.state.llm_call_count == 2 and result.state.sql_attempt_count == 2
    outcomes = [(r.phase, r.outcome) for r in audit.records]
    # SQL sai chỉ bị gate từ chối; chỉ SQL đã sửa mới được thực thi.
    assert outcomes == [("gate", "denied"), ("gate", "allowed"), ("execute", "executed")]
    assert {r.run_id for r in audit.records} == {result.state.run_id}
    assert [e.event_type for e in events.events].count("repair_started") == 1


def test_database_permission_error_is_terminal_and_not_repaired(database):  # noqa: F811
    # Policy của role sales cho đọc payments.amount_vnd, nhưng DSN trỏ tới login của operations:
    # quyền database là ranh giới độc lập và phải chặn ngay cả khi gate cho qua.
    audit = InMemoryAuditSink()
    events = InMemoryEventSink()
    planner = ScriptedRepairPlanner("SELECT amount_vnd FROM payments", [ORDERS_SQL])
    result = run(make_controller("sales", database["operations"], planner, audit, events))

    assert result.state.status == RunStatus.FAILED
    assert result.state.failure_reason == "db_permission_denied"
    assert result.state.final_answer is None
    assert planner.feedback == [] and result.state.llm_call_count == 1
    assert result.state.tool_call_count == 1 and result.state.retry_count == 0
    assert [(r.phase, r.outcome) for r in audit.records][-1] == ("execute", "db_error")
    assert audit.records[-1].error_category == "db_permission_denied"


def test_unreachable_database_follows_retry_budget_without_mock_fallback(database):  # noqa: F811
    dead_dsn = conninfo.make_conninfo(database["sales"], host="127.0.0.1", port=1)
    audit = InMemoryAuditSink()
    planner = ScriptedRepairPlanner(ORDERS_SQL, [ORDERS_SQL])
    budget = ExecutionBudget(max_retries=1)
    result = run(make_controller("sales", dead_dsn, planner, audit, budget=budget))

    assert result.state.status == RunStatus.FAILED
    assert result.state.failure_reason == "db_unavailable"
    assert result.state.final_answer is None and "demo_value" not in str(result.state)
    # db_unavailable là lỗi retry được nhưng bị chặn bởi max_retries, và không gọi lại planner.
    assert result.state.tool_call_count == 2 and result.state.retry_count == 1
    assert planner.feedback == [] and result.state.llm_call_count == 1


def test_events_and_audit_do_not_leak_credentials_rows_or_internal_errors(database):  # noqa: F811
    dsn = database["sales"]
    # Chỉ gồm dữ liệu nhạy cảm thật sự (mật khẩu, DSN, SQL gốc). Không đưa "completed" vào đây vì
    # đó là trạng thái hợp lệ của event (status="completed", context_retrieval_completed...).
    secrets_to_hide = [
        conninfo.conninfo_to_dict(dsn)["password"],
        dsn,
        ORDERS_SQL,
        "SELECT amount_vnd FROM payments",
    ]
    audit = InMemoryAuditSink()
    events = InMemoryEventSink()
    ok = make_controller(
        "sales", dsn, ScriptedRepairPlanner(ORDERS_SQL, [ORDERS_SQL]), audit, events
    )
    assert run(ok).succeeded

    failing_audit = InMemoryAuditSink()
    failing_events = InMemoryEventSink()
    bad = make_controller(
        "sales",
        database["operations"],
        ScriptedRepairPlanner("SELECT amount_vnd FROM payments", [ORDERS_SQL]),
        failing_audit,
        failing_events,
    )
    failed = run(bad)
    assert failed.state.failure_reason == "db_permission_denied"

    dumped = " ".join(
        repr(item)
        for item in (
            audit.records,
            events.events,
            failing_audit.records,
            failing_events.events,
            failed.state.errors,
            failed.state.failure_reason,
        )
    )
    for secret in secrets_to_hide:
        assert secret not in dumped
    for fragment in ("SELECT", "psycopg", "permission denied for", "Traceback"):
        assert fragment not in dumped


def test_concurrent_runs_with_different_roles_stay_isolated_on_real_database(database):  # noqa: F811
    audit = InMemoryAuditSink()
    sales = make_controller(
        "sales", database["sales"], ScriptedRepairPlanner(ORDERS_SQL, [ORDERS_SQL]), audit
    )
    finance = make_controller(
        "finance",
        database["finance"],
        ScriptedRepairPlanner(
            "SELECT payment_id, bank_reference FROM payments ORDER BY 1", [ORDERS_SQL]
        ),
        audit,
    )
    # Sales không được đọc bank_reference: gate chặn trước khi tới database, dù chạy song song.
    sales_denied = make_controller(
        "sales",
        database["sales"],
        ScriptedRepairPlanner("SELECT bank_reference FROM payments", [ORDERS_SQL]),
        audit,
    )

    async def go():
        return await asyncio.gather(
            sales.run(AgentRequest("1")),
            finance.run(AgentRequest("2")),
            sales_denied.run(AgentRequest("3")),
        )

    r_sales, r_finance, r_denied = asyncio.run(go())
    assert r_sales.succeeded and r_finance.succeeded and not r_denied.succeeded
    assert "CANARY-BANK-0001" in r_finance.state.final_answer
    assert "CANARY-BANK" not in r_sales.state.final_answer
    assert r_denied.state.tool_call_count == 0
    roles = {}
    for record in audit.records:
        roles.setdefault(record.run_id, set()).add(record.role)
    assert roles == {
        r_sales.state.run_id: {"sales"},
        r_finance.state.run_id: {"finance"},
        r_denied.state.run_id: {"sales"},
    }
