import asyncio
from contextlib import contextmanager

import pytest

from sqlguard.agent.planning import OllamaPlanner
from sqlguard.agent.postgres_schema import PostgresSchemaAdapter, SchemaAdapterError
from sqlguard.agent.schema import SchemaColumn, SchemaContext, SchemaTable
from sqlguard.security.policy import load_default_policy

SECRET_DSN = "postgresql://sales_user:s3cret-pw@db.internal:5432/sales"

# Dữ liệu giả lập mô phỏng kết quả của information_schema.columns. Cố ý để lộn xộn thứ tự
# và có cả bảng/cột mà role 'sales' KHÔNG được phép (customers.phone_number,
# customers.identity_number, payments.bank_reference, secret_table) để kiểm tra việc lọc.
# Mỗi dòng có dạng (table, column, data_type, udt_name, ordinal_position) như information_schema.
ALL_ROWS = [
    ("orders", "status", "text", "text", 3),
    ("orders", "order_id", "integer", "int4", 1),
    ("orders", "customer_id", "integer", "int4", 2),
    ("customers", "phone_number", "text", "text", 3),
    ("customers", "identity_number", "text", "text", 4),
    ("customers", "full_name", "text", "text", 2),
    ("customers", "customer_id", "integer", "int4", 1),
    ("payments", "bank_reference", "text", "text", 4),
    ("payments", "amount_vnd", "numeric", "numeric", 2),
    ("payments", "payment_id", "integer", "int4", 1),
    ("secret_table", "x", "text", "text", 1),
]


# --- Các lớp giả (fake) thay cho psycopg: giúp test chạy mà không cần PostgreSQL thật ---


# Con trỏ giả: ghi lại mọi câu SQL + tham số đã chạy, và có thể giả lập lỗi khi truy vấn.
class FakeCursor:
    def __init__(self, conn):
        self._conn = conn

    def __enter__(self):
        return self

    def __exit__(self, *args):
        return False

    def execute(self, sql, params=None):
        self._conn.executed.append((sql, params))
        if self._conn.error and "information_schema" in sql:
            raise self._conn.error

    def fetchall(self):
        return list(self._conn.rows)


# Kết nối giả: lưu các câu lệnh đã thực thi, cờ read_only và việc có rollback hay không.
class FakeConnection:
    def __init__(self, rows, error=None):
        self.rows = rows
        self.error = error
        self.executed = []
        self.read_only = False
        self.rolled_back = False

    def cursor(self):
        return FakeCursor(self)

    def rollback(self):
        self.rolled_back = True


# Connector giả: ghi lại (dsn, connect_timeout) được truyền vào, và có thể giả lập lỗi
# ngay khi kết nối (connect_error).
class FakeConnector:
    def __init__(self, rows=ALL_ROWS, error=None, connect_error=None):
        self.conn = FakeConnection(rows, error)
        self.connect_error = connect_error
        self.calls = []

    def __call__(self, dsn, connect_timeout):
        self.calls.append((dsn, connect_timeout))
        if self.connect_error:
            raise self.connect_error

        @contextmanager
        def manager():
            yield self.conn

        return manager()


# Tạo adapter cho role 'sales' với DSN giả; mật khẩu 's3cret-pw' dùng để kiểm tra rò rỉ.
def adapter(connector, **kwargs):
    return PostgresSchemaAdapter({"sales": SECRET_DSN}, connector=connector, **kwargs)


# Lỗi giả có thuộc tính sqlstate, mô phỏng lỗi của psycopg.
class SqlStateError(Exception):
    def __init__(self, message, sqlstate):
        super().__init__(message)
        self.sqlstate = sqlstate


# Chuyển metadata thành SchemaContext đúng kiểu; thứ tự bảng/cột cố định dù dòng đầu vào
# bị đảo ngược.
def test_converts_metadata_to_schema_context_with_deterministic_order():
    connector = FakeConnector()
    context = adapter(connector).load_sync("sales")
    assert isinstance(context, SchemaContext)
    assert context.dialect == "postgres"
    assert [table.name for table in context.tables] == ["customers", "orders", "payments"]
    orders = context.tables[1]
    assert orders == SchemaTable(
        "orders",
        (
            SchemaColumn("order_id", "integer"),
            SchemaColumn("customer_id", "integer"),
            SchemaColumn("status", "text"),
        ),
    )
    reversed_rows = FakeConnector(rows=list(reversed(ALL_ROWS)))
    assert adapter(reversed_rows).load_sync("sales") == context
    assert context.to_prompt_text() == adapter(connector).load_sync("sales").to_prompt_text()


# Bảng/cột ngoài policy của role không được xuất hiện trong context lẫn prompt.
def test_role_policy_filters_tables_and_columns():
    policy = load_default_policy()
    context = adapter(FakeConnector()).load_sync("sales")
    names = {table.name: {c.name for c in table.columns} for table in context.tables}
    assert "secret_table" not in names
    assert "phone_number" not in names["customers"]  # role sales không được đọc cột này
    assert "identity_number" not in names["customers"]
    assert "bank_reference" not in names["payments"]
    for table, columns in names.items():
        assert columns <= policy.allowed_columns("sales", table)
    prompt = context.to_prompt_text()
    for hidden in ("phone_number", "identity_number", "bank_reference", "secret_table"):
        assert hidden not in prompt


# Role khác (operations) thấy tập cột khác: có phone_number, nhưng không có bảng payments.
def test_different_role_sees_its_own_columns():
    connector = FakeConnector()
    operations = PostgresSchemaAdapter({"operations": "postgresql://ops"}, connector=connector)
    names = {t.name: {c.name for c in t.columns} for t in operations.load_sync("operations").tables}
    assert "phone_number" in names["customers"]
    assert "payments" not in names  # operations không được cấp bảng này


# Kiểm tra: kết nối READ ONLY, có rollback, timeout đúng, và tên schema/bảng đi qua tham số
# (không xuất hiện trong chuỗi SQL).
def test_queries_are_parameterized_and_read_only():
    connector = FakeConnector()
    adapter(connector, connect_timeout_seconds=7, statement_timeout_seconds=2).load_sync("sales")
    assert connector.calls == [(SECRET_DSN, 7)]
    assert connector.conn.read_only is True
    assert connector.conn.rolled_back is True
    timeout_call, metadata_call = connector.conn.executed
    assert timeout_call[1] == ("2000ms",)
    sql, params = metadata_call
    assert "%s" in sql and "information_schema.columns" in sql
    assert params[0] == "public"
    assert params[1] == sorted(load_default_policy().allowed_tables("sales"))
    assert "orders" not in sql and "public" not in sql  # tên định danh đi qua tham số


# Chọn bảng tường minh: bảng bị cấm, chuỗi tấn công SQL, danh sách rỗng hay chuỗi đơn đều
# bị từ chối bằng lỗi an toàn (không nêu chi tiết).
def test_explicit_table_selection_is_validated():
    connector = FakeConnector()
    context = adapter(connector).load_sync("sales", ["orders"])
    assert [t.name for t in context.tables] == ["orders"]
    assert connector.conn.executed[-1][1][1] == ["orders"]
    for bad in (["secret_table"], ["orders", "x'; DROP TABLE orders;--"], [], "orders"):
        with pytest.raises(SchemaAdapterError) as info:
            adapter(FakeConnector()).load_sync("sales", bad)
        assert info.value.category in {"schema_table_not_allowed", "schema_invalid_config"}
        assert "DROP" not in str(info.value)


# Kiểu USER-DEFINED (enum) được thay bằng tên kiểu thật từ udt_name.
def test_user_defined_types_use_udt_name():
    rows = [("orders", "status", "USER-DEFINED", "order_status", 1)]
    context = adapter(FakeConnector(rows=rows)).load_sync("sales")
    assert context.tables[0].columns[0].data_type == "order_status"


# Schema trống/không tồn tại, hoặc mọi dòng đều bị policy lọc hết -> lỗi schema_empty.
@pytest.mark.parametrize(
    "rows",
    [[], [("secret_table", "x", "text", "text", 1)], [("customers", "phone_number", "t", "t", 1)]],
)
def test_empty_or_missing_schema_is_a_safe_error(rows):
    with pytest.raises(SchemaAdapterError) as info:
        adapter(FakeConnector(rows=rows)).load_sync("sales")
    assert info.value.category == "schema_empty"


# Dòng metadata thiếu cột (sai cấu trúc) -> lỗi schema_invalid_metadata, không crash.
def test_malformed_metadata_is_a_safe_error():
    with pytest.raises(SchemaAdapterError) as info:
        adapter(FakeConnector(rows=[("orders", "status", "text", "text")])).load_sync("sales")
    assert info.value.category == "schema_invalid_metadata"


# Mỗi loại lỗi (timeout, thiếu quyền, mất kết nối, lỗi khác) ở cả bước kết nối và bước
# truy vấn đều phải ánh xạ sang đúng nhóm lỗi an toàn.
@pytest.mark.parametrize(
    ("error", "category", "retryable"),
    [
        (
            SqlStateError("canceling statement due to statement timeout", "57014"),
            "schema_timeout",
            True,
        ),
        (TimeoutError("took too long"), "schema_timeout", True),
        (
            SqlStateError("permission denied for table orders", "42501"),
            "schema_permission_denied",
            False,
        ),
        (ConnectionRefusedError("refused s3cret-pw"), "schema_unavailable", True),
        (SqlStateError("connection failure", "08006"), "schema_unavailable", True),
        (RuntimeError('relation "orders" has secret s3cret-pw'), "schema_error", False),
    ],
)
@pytest.mark.parametrize("phase", ["connect", "query"])
def test_failures_map_to_safe_categories(error, category, retryable, phase):
    connector = (
        FakeConnector(connect_error=error) if phase == "connect" else FakeConnector(error=error)
    )
    with pytest.raises(SchemaAdapterError) as info:
        adapter(connector).load_sync("sales")
    assert info.value.category == category
    assert info.value.retryable is retryable
    # Lỗi trả ra không được chứa mật khẩu, DSN hay tên bảng từ thông điệp gốc, và không
    # được giữ exception gốc (__cause__) để tránh lộ thông tin.
    text = repr(info.value) + str(info.value)
    assert "s3cret-pw" not in text and SECRET_DSN not in text and "orders" not in text
    assert info.value.__cause__ is None and info.value.__suppress_context__


# Lỗi OperationalError (nhận diện theo tên lớp) được coi là database không khả dụng.
def test_operational_error_by_class_name_is_unavailable():
    class OperationalError(Exception):
        pass

    with pytest.raises(SchemaAdapterError) as info:
        adapter(
            FakeConnector(connect_error=OperationalError("host=db password=s3cret-pw"))
        ).load_sync("sales")
    assert info.value.category == "schema_unavailable"


# Cấu hình sai: role lạ, role chưa có DSN, DSN rỗng, timeout không hợp lệ, schema rỗng.
def test_invalid_configuration():
    with pytest.raises(SchemaAdapterError) as info:
        adapter(FakeConnector()).load_sync("nobody")
    assert info.value.category == "schema_unknown_role"
    with pytest.raises(SchemaAdapterError) as info:
        PostgresSchemaAdapter({}, connector=FakeConnector()).load_sync("sales")
    assert info.value.category == "schema_role_unconfigured"
    with pytest.raises(SchemaAdapterError) as info:
        PostgresSchemaAdapter({"sales": ""}, connector=FakeConnector()).load_sync("sales")
    assert info.value.category == "schema_role_unconfigured"
    for kwargs in (
        {"connect_timeout_seconds": 0},
        {"connect_timeout_seconds": "5"},
        {"statement_timeout_seconds": 0},
        {"schema": "  "},
    ):
        with pytest.raises(SchemaAdapterError) as info:
            adapter(FakeConnector(), **kwargs)
        assert info.value.category == "schema_invalid_config"


# from_env đọc DSN theo từng role từ biến môi trường; role không có biến thì báo chưa cấu hình.
def test_from_env_reads_per_role_dsn_and_never_hardcodes():
    env = {"SQLGUARD_DB_DSN_SALES": SECRET_DSN}
    connector = FakeConnector()
    built = PostgresSchemaAdapter.from_env(env=env, connector=connector)
    built.load_sync("sales")
    assert connector.calls[0][0] == SECRET_DSN
    with pytest.raises(SchemaAdapterError) as info:
        built.load_sync("finance")
    assert info.value.category == "schema_role_unconfigured"


# Bản async hoạt động như bản sync; thiếu psycopg thì báo schema_driver_missing.
def test_async_load_and_missing_driver(monkeypatch):
    context = asyncio.run(adapter(FakeConnector()).load("sales"))
    assert context.tables

    import builtins

    real_import = builtins.__import__

    def no_psycopg(name, *args, **kwargs):
        if name == "psycopg":
            raise ImportError
        return real_import(name, *args, **kwargs)

    monkeypatch.setattr(builtins, "__import__", no_psycopg)
    with pytest.raises(SchemaAdapterError) as info:
        PostgresSchemaAdapter({"sales": SECRET_DSN}).load_sync("sales")
    assert info.value.category == "schema_driver_missing"


# SchemaContext từ adapter dùng được trong prompt của OllamaPlanner và không lộ cột bị cấm.
def test_context_is_accepted_by_the_planner_prompt():
    context = adapter(FakeConnector()).load_sync("sales")
    planner = OllamaPlanner(model="m", schema_context=context)
    prompt = str(planner._build_payload("q", ()))
    assert "customers" in prompt and "full_name" in prompt
    assert "phone_number" not in prompt and "identity_number" not in prompt


# Hồi quy: tên viết hoa/thường khác chuẩn ("ORDERS", "Status") là đối tượng khác trong
# PostgreSQL, không được thừa hưởng quyền của 'orders'/'status'.
def test_quoted_mixed_case_catalog_names_do_not_inherit_permissions():
    rows = [
        ("ORDERS", "order_id", "integer", "int4", 1),
        ("orders", "order_id", "integer", "int4", 1),
        ("orders", "Status", "text", "text", 2),
        ("orders", "status", "text", "text", 3),
    ]
    context = adapter(FakeConnector(rows=rows)).load_sync("sales")
    assert [t.name for t in context.tables] == ["orders"]
    assert [(c.name, c.data_type) for c in context.tables[0].columns] == [
        ("order_id", "integer"),
        ("status", "text"),
    ]
