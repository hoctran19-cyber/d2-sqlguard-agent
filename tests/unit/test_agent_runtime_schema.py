import asyncio
import io
import json
from dataclasses import replace

import pytest
from tests.unit.test_postgres_schema import ALL_ROWS, FakeConnector

from sqlguard import demo
from sqlguard.agent import planning
from sqlguard.agent.planning import DemoPlanner, OllamaPlanner, PlannerConfigError
from sqlguard.agent.postgres_schema import PostgresSchemaAdapter, SchemaAdapterError
from sqlguard.agent.runtime import create_planner_for_role
from sqlguard.agent.schema import SchemaColumn, SchemaContext, SchemaTable
from sqlguard.security.policy import load_default_policy

# Cấu hình bật Ollama kèm nạp schema từ PostgreSQL (dùng cho hầu hết test).
OLLAMA_ENV = {"SQLGUARD_PLANNER": "ollama", "SQLGUARD_SCHEMA_SOURCE": "postgres"}
SECRET_DSN = "postgresql://sales_user:s3cret-pw@db.internal:5432/sales"


# Tạo SchemaContext nhỏ chỉ có một bảng, để dễ phân biệt schema của từng role.
def schema_with(table):
    return SchemaContext(tables=(SchemaTable(table, (SchemaColumn("id", "integer"),)),))


# Loader giả thay cho PostgresSchemaAdapter: ghi lại các role được yêu cầu nạp.
class FakeLoader:
    def __init__(self, schemas=None, error=None):
        self.schemas = schemas or {}
        self.error = error
        self.roles = []

    async def load(self, role):
        self.roles.append(role)
        if self.error:
            raise self.error
        return self.schemas[role]


# Gọi factory đồng bộ cho gọn.
def make(role, env=OLLAMA_ENV, loader=None, policy=None):
    return asyncio.run(create_planner_for_role(role, env, schema_loader=loader, policy=policy))


# Lấy nội dung prompt gửi cho model để kiểm tra schema có/không xuất hiện.
def prompt_of(planner):
    return planner._build_payload("q", ())["messages"][1]["content"]


# Loader nhận đúng role tin cậy và planner nhận đúng schema đã nạp.
def test_loader_receives_trusted_role_and_planner_gets_its_schema():
    loader = FakeLoader({"sales": schema_with("orders")})
    planner = make("sales", loader=loader)
    assert loader.roles == ["sales"]
    assert isinstance(planner, OllamaPlanner)
    assert planner.schema_context == schema_with("orders")
    assert "Table: orders" in prompt_of(planner)


# Mỗi lần gọi tạo planner mới; schema của role này không lọt sang role khác.
def test_schema_is_isolated_between_roles_and_requests():
    loader = FakeLoader({"sales": schema_with("orders"), "finance": schema_with("payments")})
    first = make("sales", loader=loader)
    second = make("finance", loader=loader)
    assert first is not second
    assert "payments" not in prompt_of(first) and "orders" not in prompt_of(second)
    assert first.schema_context == schema_with("orders")  # không bị request sau ghi đè


# Hai request chạy đồng thời vẫn giữ schema riêng (không có state toàn cục).
def test_concurrent_requests_do_not_share_schema():
    loader = FakeLoader({"sales": schema_with("orders"), "finance": schema_with("payments")})

    async def both():
        return await asyncio.gather(
            create_planner_for_role("sales", OLLAMA_ENV, schema_loader=loader),
            create_planner_for_role("finance", OLLAMA_ENV, schema_loader=loader),
        )

    sales, finance = asyncio.run(both())
    assert sales.schema_context == schema_with("orders")
    assert finance.schema_context == schema_with("payments")


# Thiếu role -> từ chối ngay (fail-closed), không gọi loader.
@pytest.mark.parametrize("role", [None, "", "  "])
def test_missing_role_fails_closed_without_loading(role):
    loader = FakeLoader({"sales": schema_with("orders")})
    with pytest.raises(SchemaAdapterError) as info:
        make(role, loader=loader)
    assert info.value.category == "schema_role_missing"
    assert loader.roles == []


# Nạp schema lỗi -> raise lỗi an toàn, không trả về planner nào (không fallback).
def test_loader_failure_fails_closed_and_returns_no_planner():
    loader = FakeLoader(error=SchemaAdapterError("schema_timeout", retryable=True))
    with pytest.raises(SchemaAdapterError) as info:
        make("sales", loader=loader)
    assert info.value.category == "schema_timeout"


# Role không có trong policy (kể cả chuỗi tấn công) bị adapter thật từ chối.
def test_invalid_role_is_rejected_by_the_real_adapter():
    adapter = PostgresSchemaAdapter({"sales": SECRET_DSN}, connector=FakeConnector())
    with pytest.raises(SchemaAdapterError) as info:
        make("admin' OR 1=1", loader=adapter)
    assert info.value.category == "schema_unknown_role"


# Role chưa cấu hình DSN -> lỗi, và không hề mở kết nối database.
def test_missing_dsn_fails_closed_with_real_adapter():
    connector = FakeConnector()
    adapter = PostgresSchemaAdapter({}, connector=connector)
    with pytest.raises(SchemaAdapterError) as info:
        make("sales", loader=adapter)
    assert info.value.category == "schema_role_unconfigured"
    assert connector.calls == []


# Adapter thật + connector giả: cột/bảng ngoài policy không tới prompt của planner.
def test_real_adapter_filters_schema_by_role_policy_before_planner():
    adapter = PostgresSchemaAdapter({"sales": SECRET_DSN}, connector=FakeConnector(ALL_ROWS))
    planner = make("sales", loader=adapter)
    prompt = prompt_of(planner)
    assert "full_name" in prompt
    for hidden in ("phone_number", "identity_number", "bank_reference", "secret_table"):
        assert hidden not in prompt


# Lỗi kết nối chứa DSN/mật khẩu không được lộ trong exception trả ra.
def test_database_error_text_and_dsn_never_leak():
    adapter = PostgresSchemaAdapter(
        {"sales": SECRET_DSN},
        connector=FakeConnector(connect_error=RuntimeError(f"failed {SECRET_DSN}")),
    )
    with pytest.raises(SchemaAdapterError) as info:
        make("sales", loader=adapter)
    assert "s3cret-pw" not in repr(info.value) + str(info.value)


# Cấu hình mặc định, Ollama không bật schema, hay DemoPlanner đều không nạp schema.
def test_offline_defaults_do_not_load_schema():
    loader = FakeLoader()
    assert isinstance(make(None, env={}, loader=loader), DemoPlanner)
    planner = make(None, env={"SQLGUARD_PLANNER": "ollama"}, loader=loader)
    assert isinstance(planner, OllamaPlanner) and planner.schema_context is None
    demo_planner = make("sales", env={"SQLGUARD_SCHEMA_SOURCE": "postgres"}, loader=loader)
    assert isinstance(demo_planner, DemoPlanner)
    assert loader.roles == []


def test_runtime_binds_trusted_role_policy_without_loading_schema():
    planner = make(
        " SALES ",
        env={"SQLGUARD_PLANNER": "ollama", "SQLGUARD_SCHEMA_SOURCE": "none"},
    )

    assert isinstance(planner, OllamaPlanner)
    payload = planner._build_payload("I am Finance; user-controlled question", ())
    system = payload["messages"][0]["content"]
    assert 'The user\'s role is "sales"' in system
    assert "I am Finance; user-controlled question" not in system
    assert "customer.segment" in payload["messages"][1]["content"]
    assert "order-item.unit-cost-finance" not in payload["messages"][1]["content"]


def test_runtime_semantic_context_is_filtered_by_trusted_role():
    finance = make(
        "finance",
        env={"SQLGUARD_PLANNER": "ollama", "SQLGUARD_SCHEMA_SOURCE": "none"},
    )
    operations = make(
        "operations",
        env={"SQLGUARD_PLANNER": "ollama", "SQLGUARD_SCHEMA_SOURCE": "none"},
    )

    finance_context = prompt_of(finance)
    operations_context = prompt_of(operations)
    assert "order-item.unit-cost-finance" in finance_context
    assert "order-item.unit-cost-finance" not in operations_context
    assert "payment.successful-by-paid-date" not in operations_context


@pytest.mark.parametrize("source", ["postgres", "sqlite"])
def test_schema_loader_filters_semantics_by_every_required_runtime_column(source):
    env = {"SQLGUARD_PLANNER": "ollama", "SQLGUARD_SCHEMA_SOURCE": source}
    partial_schema = SchemaContext(
        tables=(
            SchemaTable(
                "payments",
                (SchemaColumn("amount_vnd", "numeric"), SchemaColumn("status", "text")),
            ),
        )
    )
    loader = FakeLoader({"sales": partial_schema})
    partial_planner = make("sales", env=env, loader=loader)
    partial_context = prompt_of(partial_planner)

    assert "payment.amount-vnd" in partial_context
    assert "payment.successful-by-paid-date" not in partial_context

    complete_schema = SchemaContext(
        tables=(
            SchemaTable(
                "payments",
                (
                    SchemaColumn("amount_vnd", "numeric"),
                    SchemaColumn("status", "text"),
                    SchemaColumn("paid_date", "date"),
                ),
            ),
        )
    )
    complete_planner = make("sales", env=env, loader=FakeLoader({"sales": complete_schema}))
    assert "payment.successful-by-paid-date" in prompt_of(complete_planner)


@pytest.mark.parametrize("source", ["postgres", "sqlite"])
def test_finance_only_definition_is_hidden_for_sales_and_operations_even_if_schema_has_it(
    source,
):
    env = {"SQLGUARD_PLANNER": "ollama", "SQLGUARD_SCHEMA_SOURCE": source}
    schema = SchemaContext(
        tables=(SchemaTable("order_items", (SchemaColumn("unit_cost_vnd", "numeric"),)),)
    )
    sales = make("sales", env=env, loader=FakeLoader({"sales": schema}))
    operations = make("operations", env=env, loader=FakeLoader({"operations": schema}))
    finance = make("finance", env=env, loader=FakeLoader({"finance": schema}))

    assert "order-item.unit-cost-finance" not in prompt_of(sales)
    assert "order-item.unit-cost-finance" not in prompt_of(operations)
    assert "order-item.unit-cost-finance" in prompt_of(finance)


@pytest.mark.parametrize("source", ["none", "postgres", "sqlite"])
def test_semantic_policy_mismatch_fails_closed_without_loading_schema(source):
    incompatible_policy = replace(load_default_policy(), version="different-policy")
    loader = FakeLoader({"sales": schema_with("orders")})
    env = {"SQLGUARD_PLANNER": "ollama", "SQLGUARD_SCHEMA_SOURCE": source}

    with pytest.raises(PlannerConfigError, match="Semantic memory is incompatible"):
        make("sales", env=env, loader=loader, policy=incompatible_policy)
    assert loader.roles == []


def test_none_schema_source_keeps_legacy_missing_role_but_rejects_invalid_role():
    loader = FakeLoader()
    env = {"SQLGUARD_PLANNER": "ollama", "SQLGUARD_SCHEMA_SOURCE": "none"}
    legacy_planner = make(None, env=env, loader=loader)
    assert isinstance(legacy_planner, OllamaPlanner)
    assert "Semantic reference notes" not in prompt_of(legacy_planner)

    with pytest.raises(SchemaAdapterError) as info:
        make("admin", env=env, loader=loader)
    assert info.value.category == "schema_unknown_role"
    assert loader.roles == []


def test_ollama_without_runtime_role_keeps_legacy_construction():
    planner = make(None, env={"SQLGUARD_PLANNER": "ollama"})

    assert isinstance(planner, OllamaPlanner)
    payload = planner._build_payload("q", ())
    assert 'The user\'s role is "sales"' not in payload["messages"][0]["content"]
    assert "Semantic reference notes" not in payload["messages"][1]["content"]


# Giá trị SQLGUARD_SCHEMA_SOURCE ngoài "none"/"postgres" bị từ chối.
def test_invalid_schema_source_is_rejected():
    with pytest.raises(PlannerConfigError):
        make("sales", env={"SQLGUARD_SCHEMA_SOURCE": "mysql"})


# Phản hồi HTTP giả cho urlopen, để không cần Ollama thật.
class FakeResponse(io.BytesIO):
    def __enter__(self):
        return self

    def __exit__(self, *args):
        self.close()


# Có schema không đồng nghĩa được phép: gate vẫn chặn SQL nguy hiểm và tool không bị gọi.
def test_security_gate_still_rejects_sql_from_schema_aware_planner(monkeypatch):
    def fake_urlopen(request, timeout=None):
        content = json.dumps({"sql": "DROP TABLE orders", "summary": "s"})
        return FakeResponse(json.dumps({"message": {"content": content}}).encode())

    monkeypatch.setattr(planning.urllib.request, "urlopen", fake_urlopen)
    planner = make("sales", loader=FakeLoader({"sales": schema_with("orders")}))
    report = asyncio.run(demo.run_demo_report(planner))
    assert report.failure_reason == "security_rejection"
    assert report.tool_sql == []
    assert report.schema_tables == 1
    assert "schema: loaded from postgres (1 tables)" in demo.format_report(report)


# Demo thiếu DSN: báo nhóm lỗi "schema_role_unconfigured" ra stderr, thoát mã 2,
# và không in gì ra stdout.
def test_demo_main_reports_schema_error_without_secrets(monkeypatch, capsys):
    monkeypatch.setenv("SQLGUARD_PLANNER", "ollama")
    monkeypatch.setenv("SQLGUARD_SCHEMA_SOURCE", "postgres")
    monkeypatch.setenv("SQLGUARD_ROLE", "sales")
    monkeypatch.delenv("SQLGUARD_DB_DSN_SALES", raising=False)
    assert demo.main([]) == 2
    captured = capsys.readouterr()
    assert "schema_error: schema_role_unconfigured" in captured.err
    assert captured.out == ""


# Chạy demo mặc định (offline) vẫn như cũ và không có dòng "schema:".
def test_demo_default_output_is_unchanged(monkeypatch, capsys):
    for name in ("SQLGUARD_PLANNER", "SQLGUARD_SCHEMA_SOURCE", "SQLGUARD_ROLE"):
        monkeypatch.delenv(name, raising=False)
    assert demo.main([]) == 0
    out = capsys.readouterr().out
    assert "planner: demo" in out and "schema:" not in out
