"""Đọc schema PostgreSQL theo role và tạo ``SchemaContext`` đã được lọc theo policy.

Module chỉ đọc tên bảng, tên cột và kiểu dữ liệu từ ``information_schema``, không đọc dữ liệu
(row) của người dùng. Policy của role quyết định bảng/cột nào được phép lộ ra: danh sách cho
phép được gửi dưới dạng tham số truy vấn (không bao giờ nối tên định danh vào chuỗi SQL) và
được áp dụng lại lên các dòng trả về, nên bảng hoặc cột bị cấm không bao giờ tới planner, kể
cả khi database trả về chúng.

Mỗi lần gọi dùng DSN runtime riêng của role (``SQLGUARD_DB_DSN_<ROLE>``) trong transaction
READ ONLY, có giới hạn thời gian kết nối và statement timeout. Thông điệp lỗi gốc của database
và DSN không bao giờ được truyền ra ngoài; mọi lỗi được quy về các nhóm lỗi chung của
``SchemaAdapterError``.

Luồng xử lý: kiểm tra role -> chọn bảng được phép -> mở kết nối chỉ đọc bằng DSN của role
-> truy vấn ``information_schema.columns`` bằng tham số -> lọc lại theo policy -> dựng
``SchemaContext`` có thứ tự cố định.
"""

from __future__ import annotations

import asyncio
import os
from collections.abc import Callable, Iterable, Mapping
from contextlib import AbstractContextManager
from typing import Any

from sqlguard.agent.schema import SchemaColumn, SchemaContext, SchemaTable
from sqlguard.security.policy import RolePolicy, load_default_policy
from sqlguard.security.postgres import DSN_ENV_PREFIX

# Truy vấn metadata duy nhất của adapter. Mọi giá trị (schema, danh sách bảng) được truyền
# qua tham số %s nên không có nguy cơ SQL injection. ORDER BY giúp kết quả ổn định.
# ``ANY(%s)`` nhận một mảng tên bảng; mảng này luôn lấy từ allow-list của policy.
_COLUMNS_SQL = (
    "SELECT table_name, column_name, data_type, udt_name, ordinal_position "
    "FROM information_schema.columns "
    "WHERE table_schema = %s AND table_name = ANY(%s) "
    "ORDER BY table_name, ordinal_position, column_name"
)
# Mã SQLSTATE của PostgreSQL dùng để phân loại lỗi (không dựa vào thông điệp lỗi):
# 57014 = truy vấn bị hủy do quá statement_timeout.
_SQLSTATE_QUERY_CANCELED = "57014"
# 42501 = thiếu quyền; 28000/28P01 = xác thực thất bại (sai tài khoản/mật khẩu).
_PERMISSION_SQLSTATES = ("42501", "28000", "28P01")

# Hàm tạo kết nối: nhận (dsn, connect_timeout) và trả về context manager của connection.
# Mặc định dùng psycopg; unit test truyền connector giả nên không cần PostgreSQL thật.
Connector = Callable[[str, int], AbstractContextManager[Any]]


class SchemaAdapterError(Exception):
    """Lỗi "an toàn": chỉ chứa tên nhóm lỗi (ví dụ ``schema_timeout``), tuyệt đối không chứa
    DSN, mật khẩu hay thông điệp gốc của database. ``retryable`` cho biết có nên thử lại
    hay không (lỗi tạm thời như timeout/mất kết nối thì True).
    """

    def __init__(self, category: str, *, retryable: bool = False) -> None:
        super().__init__(category)
        self.category = category
        self.retryable = retryable


def _default_connector(dsn: str, connect_timeout: int) -> AbstractContextManager[Any]:
    # Import trễ: psycopg là dependency tùy chọn (extra ``postgres``), thiếu thì báo lỗi gọn.
    try:
        import psycopg
    except ImportError:
        raise SchemaAdapterError("schema_driver_missing") from None
    return psycopg.connect(dsn, connect_timeout=connect_timeout)


class PostgresSchemaAdapter:
    """Đọc schema PostgreSQL theo role và trả về ``SchemaContext`` đã được lọc theo policy.

    Mỗi role dùng DSN riêng (quyền DB riêng), nên ngay cả khi lọc lỗi thì database vẫn
    giới hạn những gì role đó nhìn thấy (phòng thủ nhiều lớp).
    """

    def __init__(
        self,
        dsn_by_role: Mapping[str, str],
        policy: RolePolicy | None = None,
        *,
        schema: str | None = None,
        connect_timeout_seconds: int = 5,
        statement_timeout_seconds: float = 3.0,
        connector: Connector | None = None,
    ) -> None:
        # Kiểm tra cấu hình ngay khi khởi tạo: timeout phải là số dương (bounded timeout).
        if not isinstance(connect_timeout_seconds, int) or connect_timeout_seconds <= 0:
            raise SchemaAdapterError("schema_invalid_config")
        # Viết ``not x > 0`` (thay vì ``x <= 0``) để NaN cũng bị từ chối.
        if not statement_timeout_seconds > 0:
            raise SchemaAdapterError("schema_invalid_config")
        self._policy = policy or load_default_policy()
        # Schema mặc định lấy từ policy ("public"); có thể ghi đè một cách tường minh.
        self._schema = (schema or self._policy.schema).casefold()
        if not self._schema.strip():
            raise SchemaAdapterError("schema_invalid_config")
        # Chuẩn hóa tên role về chữ thường; bỏ qua DSN rỗng để coi như "chưa cấu hình".
        self._dsns = {role.casefold(): dsn for role, dsn in dsn_by_role.items() if dsn}
        self._connect_timeout = connect_timeout_seconds
        # Đổi giây sang mili-giây cho ``statement_timeout`` của PostgreSQL (tối thiểu 1ms).
        self._statement_timeout_ms = max(1, int(statement_timeout_seconds * 1000))
        self._connector = connector or _default_connector

    @classmethod
    def from_env(
        cls,
        policy: RolePolicy | None = None,
        *,
        env: Mapping[str, str] | None = None,
        **options: Any,
    ) -> PostgresSchemaAdapter:
        """Đọc DSN từ biến môi trường theo từng role trong policy (cùng quy ước với
        ``PostgresExecutor``); không bao giờ ghi cứng thông tin đăng nhập trong code.
        """
        env = os.environ if env is None else env
        policy = policy or load_default_policy()
        dsns = {
            role: env[DSN_ENV_PREFIX + role.upper()]
            for role in policy.roles
            if env.get(DSN_ENV_PREFIX + role.upper())
        }
        return cls(dsns, policy, **options)

    async def load(self, role: str, tables: Iterable[str] | None = None) -> SchemaContext:
        # Driver psycopg là đồng bộ (blocking) nên chạy trong thread để không chặn event loop.
        return await asyncio.to_thread(self.load_sync, role, tables)

    def load_sync(self, role: str, tables: Iterable[str] | None = None) -> SchemaContext:
        """Trả về schema mà ``role`` được phép thấy; ``tables`` (tùy chọn) thu hẹp danh sách."""
        # Bước 1: role phải tồn tại trong policy.
        if not isinstance(role, str) or not self._policy.has_role(role):
            raise SchemaAdapterError("schema_unknown_role")
        # Bước 2: xác định các bảng được phép (kiểm tra TRƯỚC khi chạm vào database).
        selected = self._select_tables(role, tables)
        # Bước 3: role phải có DSN riêng được cấu hình.
        dsn = self._dsns.get(role.casefold())
        if dsn is None:
            raise SchemaAdapterError("schema_role_unconfigured")
        # Bước 4: truy vấn metadata, bước 5: lọc lại theo policy và dựng SchemaContext.
        rows = self._fetch(dsn, selected)
        return self._build(role, selected, rows)

    def _select_tables(self, role: str, requested: Iterable[str] | None) -> tuple[str, ...]:
        """Giao giữa bảng được yêu cầu và allow-list của role; luôn sắp xếp để ổn định."""
        allowed = self._policy.allowed_tables(role)
        if requested is None:
            return tuple(sorted(allowed))
        # Một chuỗi đơn (vd "orders") sẽ bị duyệt từng ký tự nếu không chặn ở đây.
        if isinstance(requested, str):
            raise SchemaAdapterError("schema_invalid_config")
        wanted = {name.casefold() for name in requested if isinstance(name, str)}
        # Bảng không tồn tại hoặc bị cấm đều bị từ chối. Lỗi không nêu tên bảng để không
        # tiết lộ bảng nào tồn tại hoặc bị cấm.
        if not wanted or not wanted <= allowed:
            raise SchemaAdapterError("schema_table_not_allowed")
        return tuple(sorted(wanted))

    def _fetch(self, dsn: str, tables: tuple[str, ...]) -> list[tuple[Any, ...]]:
        """Mở kết nối chỉ đọc, chạy truy vấn metadata và luôn rollback."""
        try:
            with self._connector(dsn, self._connect_timeout) as conn:
                # Transaction READ ONLY: adapter không thể ghi/sửa dữ liệu.
                conn.read_only = True
                with conn.cursor() as cursor:
                    # ``set_config(..., true)`` chỉ có hiệu lực trong transaction hiện tại,
                    # giúp giới hạn thời gian chạy của truy vấn metadata.
                    cursor.execute(
                        "SELECT set_config('statement_timeout', %s, true)",
                        (f"{self._statement_timeout_ms}ms",),
                    )
                    cursor.execute(_COLUMNS_SQL, (self._schema, list(tables)))
                    rows = [tuple(row) for row in cursor.fetchall()]
                conn.rollback()
        except SchemaAdapterError:
            raise
        except Exception as error:
            # ``from None`` xóa exception gốc khỏi chuỗi lỗi để không lộ DSN/thông điệp DB.
            raise _classify(error) from None
        return rows

    def _build(
        self, role: str, selected: tuple[str, ...], rows: list[tuple[Any, ...]]
    ) -> SchemaContext:
        """Lọc lại từng dòng theo policy rồi dựng ``SchemaContext`` có thứ tự cố định."""
        permitted = set(selected)
        # bảng -> {cột: (vị trí cột, kiểu dữ liệu)}
        collected: dict[str, dict[str, tuple[int, str]]] = {}
        try:
            for table, column, data_type, udt_name, position in rows:
                table_key, column_key = str(table), str(column)
                # Định danh trong policy là chữ thường; tên viết hoa/thường lẫn lộn (có nháy kép)
                # là đối tượng khác, không được thừa hưởng quyền của định danh được phép.
                if table_key not in permitted or not self._policy.can_read(
                    role, table_key, column_key
                ):
                    continue
                if column_key != column_key.casefold():
                    continue
                # Kiểu tự định nghĩa (enum...) báo là "USER-DEFINED"; dùng udt_name để có tên thật.
                kind = str(udt_name if data_type == "USER-DEFINED" else data_type)
                collected.setdefault(table_key, {})[column_key] = (int(position), kind)
            # Thứ tự cố định: bảng theo tên, cột theo vị trí (ordinal_position) rồi theo tên,
            # nên cùng một dữ liệu luôn cho cùng một prompt bất kể thứ tự dòng trả về.
            tables = tuple(
                SchemaTable(
                    name=table,
                    columns=tuple(
                        SchemaColumn(name=column, data_type=kind)
                        for column, (_, kind) in sorted(
                            collected[table].items(), key=lambda item: (item[1][0], item[0])
                        )
                    ),
                )
                for table in sorted(collected)
            )
            # Không còn bảng/cột hợp lệ (schema trống, không tồn tại hoặc bị lọc hết).
            if not tables:
                raise SchemaAdapterError("schema_empty")
            return SchemaContext(tables=tables, dialect="postgres")
        except SchemaAdapterError:
            raise
        except (TypeError, ValueError):
            # Dòng metadata sai cấu trúc hoặc vi phạm ràng buộc của SchemaContext.
            raise SchemaAdapterError("schema_invalid_metadata") from None


def _classify(error: Exception) -> SchemaAdapterError:
    """Đổi exception bất kỳ thành nhóm lỗi an toàn; không bao giờ dùng thông điệp gốc."""
    sqlstate = str(getattr(error, "sqlstate", "") or "")
    if isinstance(error, TimeoutError) or sqlstate == _SQLSTATE_QUERY_CANCELED:
        return SchemaAdapterError("schema_timeout", retryable=True)
    if sqlstate in _PERMISSION_SQLSTATES:
        return SchemaAdapterError("schema_permission_denied")
    if isinstance(error, OSError) or sqlstate.startswith("08") or _is_operational(error):
        return SchemaAdapterError("schema_unavailable", retryable=True)
    return SchemaAdapterError("schema_error")


def _is_operational(error: Exception) -> bool:
    # So khớp theo tên lớp để không phải import psycopg (dependency tùy chọn) ở đây.
    return any(cls.__name__ == "OperationalError" for cls in type(error).__mro__)
