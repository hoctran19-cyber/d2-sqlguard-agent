"""Ghép các thành phần runtime cho từng lần chạy: planner (kèm schema) và công cụ truy vấn.

Phần 1 - planner: tạo planner cho từng request, kèm ``SchemaContext`` đã lọc theo role tin cậy.

Schema được nạp bằng ``PostgresSchemaAdapter`` hoặc ``SQLiteSchemaAdapter`` (đều áp dụng
``RolePolicy``) rồi gắn vào một ``OllamaPlanner`` MỚI cho mỗi lần gọi, nên không có state schema
dùng chung giữa các role hay request. ``role`` phải do backend lấy từ phiên đã xác thực, không
lấy từ câu hỏi hay LLM. Tính năng chỉ bật khi ``SQLGUARD_SCHEMA_SOURCE=postgres`` hoặc ``sqlite``;
mặc định không mở kết nối DB nào.
Mọi lỗi đều fail-closed bằng ``SchemaAdapterError`` (chỉ có nhóm lỗi, không lộ DSN/lỗi gốc).
Schema chỉ giúp planner chọn đúng định danh; việc cấp quyền SQL vẫn do security gate đảm nhiệm.

Phần 2 - truy vấn: ``build_query_runtime`` dựng bộ ba gate + ``SecureSqlTool`` +
``PostgresExecutor`` hoặc ``SQLiteExecutor`` cho MỘT lần chạy, cùng chung một
``SecurityContext`` tin cậy. ``SQLGUARD_QUERY_SOURCE`` (độc lập với nguồn schema) tường minh chọn
``mock``, ``postgres`` hoặc ``sqlite``; mặc định là ``mock``. Cấu hình sai thì fail-closed bằng
``QueryRuntimeError``, tuyệt đối không tự chuyển sang kết quả giả hay credential dự phòng.
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
from sqlguard.agent.sqlite_schema import SQLITE_PATH_ENV, SQLiteSchemaAdapter
from sqlguard.memory.semantic import BUSINESS_POLICY_VERSION, semantic_memory_for
from sqlguard.security.audit import AuditSink, InMemoryAuditSink, JsonlAuditSink
from sqlguard.security.gate import PolicySQLGate, SecurityContext
from sqlguard.security.policy import RolePolicy, load_default_policy
from sqlguard.security.postgres import DSN_ENV_PREFIX, PostgresExecutor
from sqlguard.security.schema_preflight import preflight_financial_sqlite
from sqlguard.security.service import ExecutorError, QueryExecutor, SecureSqlTool, find_leaks
from sqlguard.security.sqlite import SQLiteExecutor

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
    policy: RolePolicy | None = None,
) -> Planner:
    """Trả về planner mới cho một request.

    ``role`` phải là role tin cậy từ phiên đã xác thực (không phải từ câu hỏi người dùng).
    ``schema_loader`` cho phép tiêm loader giả khi test; mặc định dùng ``PostgresSchemaAdapter``
    đọc DSN theo role từ biến môi trường.
    """
    env = os.environ if env is None else env
    # Nguồn schema mặc định là "none": không mở kết nối database nào (giữ nguyên chạy offline).
    source = (env.get(SCHEMA_SOURCE_ENV) or "none").lower()
    if source not in {"none", "postgres", "sqlite"}:
        raise PlannerConfigError("SQLGUARD_SCHEMA_SOURCE must be 'none', 'postgres', or 'sqlite'")
    # Tạo planner theo SQLGUARD_PLANNER trước để biết có cần schema hay không.
    planner = create_planner(env)
    # DemoPlanner không dùng schema nên không cần (và không được) mở kết nối database.
    if not isinstance(planner, OllamaPlanner):
        return planner
    # Role/policy chỉ được lấy từ cấu hình runtime tin cậy; legacy callers vẫn có thể không có.
    if source == "none":
        if not role or not role.strip():
            return planner
        role = role.strip().casefold()
        policy = policy or load_default_policy()
        if not policy.has_role(role):
            raise SchemaAdapterError("schema_unknown_role")
        if semantic_memory_for(policy) is None:
            raise PlannerConfigError("Semantic memory is incompatible with the role policy")
        return OllamaPlanner.from_env(env, role=role, policy=policy)
    # Từ đây phải nạp schema: thiếu role thì từ chối, tuyệt đối không dùng schema không lọc.
    if not role or not role.strip():
        raise SchemaAdapterError("schema_role_missing")
    role = role.strip().casefold()
    policy = policy or load_default_policy()
    if not policy.has_role(role):
        raise SchemaAdapterError("schema_unknown_role")
    if semantic_memory_for(policy) is None:
        raise PlannerConfigError("Semantic memory is incompatible with the role policy")
    # Adapter tự kiểm tra role có trong policy, lấy DSN theo role và lọc schema theo RolePolicy.
    if schema_loader is not None:
        loader = schema_loader
    elif source == "postgres":
        loader = PostgresSchemaAdapter.from_env(policy=policy, env=env)
    else:
        loader = SQLiteSchemaAdapter.from_env(policy=policy, env=env)
    # Lỗi nạp schema (thiếu DSN, timeout, schema rỗng...) được ném thẳng ra, không fallback.
    schema = await loader.load(role)
    # Tạo planner MỚI gắn schema của đúng role này; không sửa planner nào đang dùng chung.
    return OllamaPlanner.from_env(env, schema_context=schema, policy=policy, role=role)


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
    # Policy và audit của run, dùng cho output_check; None thì không kiểm tra thêm.
    policy: RolePolicy | None = None
    audit: AuditSink | None = None

    def output_check(self, answer: str) -> bool:
        """Kiểm tra câu trả lời cuối; True nghĩa là có canary của role và phải giữ lại.

        Role lấy từ SecurityContext tin cậy của run, không từ câu hỏi hay đầu ra của model.
        Khi rò rỉ, ghi một audit record chỉ có băm/danh mục (không có câu trả lời hay giá trị
        rò); lỗi ghi audit sẽ ném ra để controller chặn kết quả (fail closed).
        """
        if self.policy is None or not find_leaks(answer, self.policy, self.context.role):
            return False
        # Mượn quyết định gate gần nhất của tool để audit mang đủ băm/policy_version của run.
        decision = self.tool.last_decision
        if self.audit is not None and decision is not None:
            self.audit.record(
                self.gate.audit_record(
                    decision,
                    phase="output",
                    attempt=0,
                    outcome="blocked",
                    error_category="canary_leak",
                )
            )
        return True


@dataclass(frozen=True)
class QueryRuntimeFactory:
    """Cấu hình truy vấn đã kiểm tra, dựng context/gate/tool MỚI cho từng run_id.

    Chỉ giữ dữ liệu bất biến hoặc đối tượng không mang trạng thái theo request (policy, executor,
    audit sink); ``SecurityContext`` và bộ đếm của gate được tạo lại trong ``for_run``.
    """

    role: str
    policy: RolePolicy
    executor: QueryExecutor
    audit: AuditSink
    source: str = "postgres"

    def for_run(
        self, run_id: str, *, user_id: str = "cli", request_mode: str = "nl"
    ) -> QueryRuntime:
        # run_id là của AgentState, nên audit của gate/tool khớp với run của controller.
        # user_id/request_mode do backend truyền từ phiên đăng nhập, chỉ dùng cho audit.
        context = SecurityContext(
            role=self.role, user_id=user_id, run_id=run_id, request_mode=request_mode
        )
        return QueryRuntime(
            context=context,
            gate=PolicySQLGate(context, self.policy, audit=self.audit),
            tool=SecureSqlTool(
                PolicySQLGate(context, self.policy), self.executor, audit=self.audit
            ),
            # Truyền policy/audit để output_check dùng đúng role và nơi ghi audit của run này.
            policy=self.policy,
            audit=self.audit,
        )


def build_query_runtime(
    role: str | None,
    env: Mapping[str, str] | None = None,
    *,
    executor: QueryExecutor | None = None,
    audit: AuditSink | None = None,
    policy: RolePolicy | None = None,
    run_id: str | None = None,
) -> QueryRuntime | None:
    """Dựng runtime cho đúng một run (``run_id`` mặc định là UUID mới); ``None`` ở chế độ mock."""
    factory = build_query_runtime_factory(role, env, executor=executor, audit=audit, policy=policy)
    return None if factory is None else factory.for_run(run_id or str(uuid4()))


def build_query_runtime_factory(
    role: str | None,
    env: Mapping[str, str] | None = None,
    *,
    executor: QueryExecutor | None = None,
    audit: AuditSink | None = None,
    policy: RolePolicy | None = None,
) -> QueryRuntimeFactory | None:
    """Trả về ``None`` ở chế độ mock; postgres/sqlite tạo runtime riêng cho từng run.

    ``role`` phải là role tin cậy (cấu hình của người vận hành/phiên đã xác thực), không bao giờ
    lấy từ câu hỏi, đầu ra LLM hay tham số của tool. ``executor`` và ``audit`` chỉ để tiêm đối
    tượng giả khi test.
    """
    env = os.environ if env is None else env
    # Mặc định "mock": giữ nguyên chạy offline, không mở kết nối database.
    source = (env.get(QUERY_SOURCE_ENV) or "mock").lower()
    if source not in {"mock", "postgres", "sqlite"}:
        raise QueryRuntimeError("query_invalid_config")
    if source == "mock":
        return None
    if not role or not role.strip():
        raise QueryRuntimeError("query_role_missing")
    role = role.strip().casefold()
    policy = policy or load_default_policy()
    if not policy.has_role(role):
        raise QueryRuntimeError("query_unknown_role")
    if source == "sqlite":
        path = env.get(SQLITE_PATH_ENV)
        if not path or not path.strip():
            raise QueryRuntimeError("query_sqlite_path_missing")
        if not os.path.isfile(os.path.expanduser(path)):
            raise QueryRuntimeError("query_sqlite_db_missing")
        # The business policy is only valid on the reviewed schema: fail closed on drift.
        if policy.version == BUSINESS_POLICY_VERSION and not preflight_financial_sqlite(path).valid:
            raise QueryRuntimeError("query_sqlite_schema_mismatch")
        if executor is None:
            try:
                # Authorizer của executor dựng từ cùng policy với gate.
                executor = SQLiteExecutor(path, policy)
            except (ExecutorError, OSError, ValueError):
                raise QueryRuntimeError("query_sqlite_db_unavailable") from None
    elif executor is None:
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
    return QueryRuntimeFactory(
        role=role,
        policy=policy,
        executor=executor,
        audit=audit,
        source=source,
    )
