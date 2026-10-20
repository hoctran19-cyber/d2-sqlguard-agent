"""Tạo planner cho từng request, kèm ``SchemaContext`` đã lọc theo role tin cậy.

Schema được nạp bằng ``PostgresSchemaAdapter`` (đã áp dụng ``RolePolicy``) rồi gắn vào một
``OllamaPlanner`` MỚI cho mỗi lần gọi, nên không có state schema dùng chung giữa các role hay
request. ``role`` phải do backend lấy từ phiên đã xác thực, không lấy từ câu hỏi hay LLM.
Tính năng chỉ bật khi ``SQLGUARD_SCHEMA_SOURCE=postgres``; mặc định không mở kết nối DB nào.
Mọi lỗi đều fail-closed bằng ``SchemaAdapterError`` (chỉ có nhóm lỗi, không lộ DSN/lỗi gốc).
Schema chỉ giúp planner chọn đúng định danh; việc cấp quyền SQL vẫn do security gate đảm nhiệm.
"""

from __future__ import annotations

import os
from collections.abc import Mapping
from typing import Protocol

from sqlguard.agent.planning import OllamaPlanner, Planner, PlannerConfigError, create_planner
from sqlguard.agent.postgres_schema import PostgresSchemaAdapter, SchemaAdapterError
from sqlguard.agent.schema import SchemaContext

SCHEMA_SOURCE_ENV = "SQLGUARD_SCHEMA_SOURCE"


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
