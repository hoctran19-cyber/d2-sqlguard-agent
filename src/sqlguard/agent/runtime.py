"""Ghép các thành phần runtime cho từng lần chạy: planner (kèm schema) và công cụ truy vấn.

Phần 1 - planner: tạo planner cho từng request, kèm ``SchemaContext`` đã lọc theo role tin cậy.

Schema được nạp bằng ``PostgresSchemaAdapter`` (đã áp dụng ``RolePolicy``) rồi gắn vào một
``OllamaPlanner`` MỚI cho mỗi lần gọi, nên không có state schema dùng chung giữa các role hay
request. ``role`` phải do backend lấy từ phiên đã xác thực, không lấy từ câu hỏi hay LLM.
Tính năng chỉ bật khi ``SQLGUARD_SCHEMA_SOURCE=postgres``; mặc định không mở kết nối DB nào.
Mọi lỗi đều fail-closed bằng ``SchemaAdapterError`` (chỉ có nhóm lỗi, không lộ DSN/lỗi gốc).
Schema chỉ giúp planner chọn đúng định danh; việc cấp quyền SQL vẫn do security gate đảm nhiệm.

Phần 2 - truy vấn: ``build_query_runtime`` dựng bộ ba gate + ``SecureSqlTool`` +
``PostgresExecutor`` cho MỘT lần chạy, cùng chung một ``SecurityContext`` tin cậy. Chỉ bật khi
``SQLGUARD_QUERY_SOURCE=postgres`` (cấu hình tách biệt với ``SQLGUARD_SCHEMA_SOURCE``); mặc định
là ``mock`` và không chạm database. Thiếu/ sai cấu hình thì fail-closed bằng ``QueryRuntimeError``,
tuyệt đối không tự chuyển sang kết quả giả hay credential dự phòng.
"""

from __future__ import annotations

import os
from collections.abc import Mapping
from dataclasses import dataclass
from importlib.util import find_spec
from typing import Protocol
from uuid import uuid4

from sqlguard.agent.planning import OllamaPlanner, Planner, PlannerConfigError, create_planner
from sqlguard.agent.postgres_schema import PostgresSchemaAdapter, SchemaAdapterError
from sqlguard.agent.schema import SchemaContext
from sqlguard.security.audit import AuditSink, InMemoryAuditSink, JsonlAuditSink
from sqlguard.security.gate import PolicySQLGate, SecurityContext
from sqlguard.security.policy import RolePolicy, load_default_policy
from sqlguard.security.postgres import DSN_ENV_PREFIX, PostgresExecutor
from sqlguard.security.service import QueryExecutor, SecureSqlTool

SCHEMA_SOURCE_ENV = "SQLGUARD_SCHEMA_SOURCE"
QUERY_SOURCE_ENV = "SQLGUARD_QUERY_SOURCE"
AUDIT_PATH_ENV = "SQLGUARD_AUDIT_PATH"


# Giao diện tối thiểu của bộ nạp schema; ``PostgresSchemaAdapter`` thỏa mãn giao diện này và
# unit test có thể thay bằng loader giả để không cần database.
class SchemaLoader(Protocol):
    async def load(self, role: str) -> SchemaContext: ...


async def create_planner_for_role(
    role: str | None,
    env: Mapping[str, str] | None = None,
    *,
    schema_loader: SchemaLoader | None = None,
) -> Planner:
    """Trả về planner mới cho một request.

    ``role`` phải là role tin cậy từ phiên đã xác thực (không phải từ câu hỏi người dùng).
    ``schema_loader`` cho phép tiêm loader giả khi test; mặc định dùng ``PostgresSchemaAdapter``
    đọc DSN theo role từ biến môi trường.
    """
    env = os.environ if env is None else env
    # Nguồn schema mặc định là "none": không mở kết nối database nào (giữ nguyên chạy offline).
    source = (env.get(SCHEMA_SOURCE_ENV) or "none").lower()
    if source not in {"none", "postgres"}:
        raise PlannerConfigError("SQLGUARD_SCHEMA_SOURCE must be 'none' or 'postgres'")
    # Tạo planner theo SQLGUARD_PLANNER trước để biết có cần schema hay không.
    planner = create_planner(env)
    # DemoPlanner không dùng schema nên không cần (và không được) mở kết nối database.
    if source == "none" or not isinstance(planner, OllamaPlanner):
        return planner
    # Từ đây phải nạp schema: thiếu role thì từ chối, tuyệt đối không dùng schema không lọc.
    if not role or not role.strip():
        raise SchemaAdapterError("schema_role_missing")
    # Adapter tự kiểm tra role có trong policy, lấy DSN theo role và lọc schema theo RolePolicy.
    loader = schema_loader or PostgresSchemaAdapter.from_env(env=env)
    # Lỗi nạp schema (thiếu DSN, timeout, schema rỗng...) được ném thẳng ra, không fallback.
    schema = await loader.load(role)
    # Tạo planner MỚI gắn schema của đúng role này; không sửa planner nào đang dùng chung.
    return OllamaPlanner.from_env(env, schema_context=schema)


class QueryRuntimeError(Exception):
    """Lỗi cấu hình truy vấn: chỉ mang tên nhóm lỗi, không chứa DSN hay thông điệp gốc."""

    def __init__(self, category: str) -> None:
        super().__init__(category)
        self.category = category


@dataclass(frozen=True)
class QueryRuntime:
    """Bộ công cụ truy vấn của MỘT lần chạy; không dùng chung giữa các role hay request."""

    context: SecurityContext
    gate: PolicySQLGate  # gate kiểm tra trước ở controller
    tool: SecureSqlTool  # ranh giới thực thi, tự kiểm tra lại policy bằng gate riêng


def build_query_runtime(
    role: str | None,
    env: Mapping[str, str] | None = None,
    *,
    executor: QueryExecutor | None = None,
    audit: AuditSink | None = None,
    policy: RolePolicy | None = None,
) -> QueryRuntime | None:
    """Trả về ``None`` ở chế độ mock; ở chế độ postgres trả về gate + SecureSqlTool của run này.

    ``role`` phải là role tin cậy (cấu hình của người vận hành/phiên đã xác thực), không bao giờ
    lấy từ câu hỏi, đầu ra LLM hay tham số của tool. ``executor`` và ``audit`` chỉ để tiêm đối
    tượng giả khi test.
    """
    env = os.environ if env is None else env
    # Mặc định "mock": giữ nguyên chạy offline, không mở kết nối database.
    source = (env.get(QUERY_SOURCE_ENV) or "mock").lower()
    if source not in {"mock", "postgres"}:
        raise QueryRuntimeError("query_invalid_config")
    if source == "mock":
        return None
    if not role or not role.strip():
        raise QueryRuntimeError("query_role_missing")
    role = role.strip().casefold()
    policy = policy or load_default_policy()
    if not policy.has_role(role):
        raise QueryRuntimeError("query_unknown_role")
    if executor is None:
        # Mỗi role dùng credential riêng; thiếu DSN thì dừng, không có credential dự phòng.
        dsn = env.get(DSN_ENV_PREFIX + role.upper())
        if not dsn:
            raise QueryRuntimeError("query_role_unconfigured")
        if find_spec("psycopg") is None:
            raise QueryRuntimeError("query_driver_missing")
        # Executor chỉ giữ DSN của đúng role này, nên không thể chạy bằng credential role khác.
        executor = PostgresExecutor({role: dsn})
    if audit is None:
        path = env.get(AUDIT_PATH_ENV)
        try:
            audit = JsonlAuditSink(path) if path else InMemoryAuditSink()
        except OSError:
            raise QueryRuntimeError("query_audit_unavailable") from None
    context = SecurityContext(role=role, user_id="cli", run_id=str(uuid4()), request_mode="nl")
    return QueryRuntime(
        context=context,
        gate=PolicySQLGate(context, policy, audit=audit),
        tool=SecureSqlTool(PolicySQLGate(context, policy), executor, audit=audit),
    )
