import json
from dataclasses import FrozenInstanceError, replace
from pathlib import Path

import pytest

from sqlguard.agent.schema import SchemaColumn, SchemaContext, SchemaTable
from sqlguard.memory.semantic import (
    DEFAULT_SEMANTIC_MEMORY,
    SEMANTIC_MEMORY_VERSION,
    SemanticMemory,
    SemanticMemoryError,
)
from sqlguard.security.policy import load_default_policy


@pytest.fixture
def policy():
    # Dùng policy chính thức của repository để các kiểm thử quyền phản ánh đúng grant thực tế.
    return load_default_policy()


def test_catalog_contains_versioned_definitions_with_repo_sources():
    """Catalog phải có đủ metadata để truy vết và kiểm soát việc dùng định nghĩa."""
    catalog = DEFAULT_SEMANTIC_MEMORY

    # Khóa số lượng 12 để phát hiện vô tình thêm/bớt định nghĩa ngoài phạm vi đã duyệt.
    assert len(catalog.definitions) == 12
    assert catalog.version == SEMANTIC_MEMORY_VERSION
    assert catalog.policy_version == "d2-synthetic-v1"
    # Mỗi entry phải cùng version với catalog và khai rõ nguồn, cột, role liên quan.
    assert all(definition.version == catalog.version for definition in catalog.definitions)
    assert all(definition.source_refs for definition in catalog.definitions)
    assert all(definition.required_columns for definition in catalog.definitions)
    assert all(definition.allowed_roles for definition in catalog.definitions)


def test_every_source_reference_resolves_inside_repository():
    """Bảo đảm mọi trích dẫn trong catalog trỏ tới file và mục có thật trong repo."""
    for definition in DEFAULT_SEMANTIC_MEMORY.definitions:
        for source_ref in definition.source_refs:
            # Tách đường dẫn file và JSON Pointer nếu nguồn tham chiếu tới một mục JSON.
            path_text, _, pointer = source_ref.partition("#")
            source_path = Path(path_text)
            assert source_path.is_file(), source_ref
            if not pointer.startswith("/"):
                continue
            value = json.loads(source_path.read_text(encoding="utf-8"))
            # Đi theo từng thành phần pointer; hỗ trợ cả object JSON lẫn phần tử mảng.
            for component in pointer.lstrip("/").split("/"):
                component = component.replace("~1", "/").replace("~0", "~")
                value = value[int(component)] if isinstance(value, list) else value[component]


def test_role_filter_uses_declared_roles_and_policy_column_grants(policy):
    """Chỉ trả định nghĩa được khai báo cho role và có đủ quyền đọc các cột cần thiết."""
    sales = DEFAULT_SEMANTIC_MEMORY.for_role("sales", policy)
    finance = DEFAULT_SEMANTIC_MEMORY.for_role("finance", policy)
    operations = DEFAULT_SEMANTIC_MEMORY.for_role("operations", policy)

    # Thanh toán không hiển thị cho Operations; giá vốn chỉ xuất hiện trong context Finance.
    sales_ids = {definition.definition_id for definition in sales}
    finance_ids = {definition.definition_id for definition in finance}
    operations_ids = {definition.definition_id for definition in operations}
    assert "payment.successful-by-paid-date" in sales_ids
    assert "payment.successful-by-paid-date" in finance_ids
    assert "payment.successful-by-paid-date" not in operations_ids
    assert "order-item.unit-cost-finance" not in sales_ids | operations_ids
    assert "order-item.unit-cost-finance" in finance_ids


def test_role_and_policy_version_must_be_trusted(policy):
    """Từ chối role không tồn tại và policy khác version với catalog."""
    with pytest.raises(SemanticMemoryError, match="trusted policy"):
        DEFAULT_SEMANTIC_MEMORY.for_role("finance", replace(policy, version="other-version"))
    with pytest.raises(SemanticMemoryError, match="trusted policy"):
        DEFAULT_SEMANTIC_MEMORY.for_role("admin", policy)
    with pytest.raises(SemanticMemoryError, match="trusted role"):
        DEFAULT_SEMANTIC_MEMORY.for_role("", policy)


def test_catalog_rejects_invalid_or_duplicate_definitions():
    """Catalog không nhận ID trùng, version không khớp hoặc thiếu metadata bắt buộc."""
    valid = DEFAULT_SEMANTIC_MEMORY.definitions[0]
    with pytest.raises(SemanticMemoryError, match="duplicate"):
        SemanticMemory(
            version=SEMANTIC_MEMORY_VERSION,
            policy_version=DEFAULT_SEMANTIC_MEMORY.policy_version,
            definitions=(valid, valid),
        )
    with pytest.raises(SemanticMemoryError, match="version"):
        SemanticMemory(
            version="other-version",
            policy_version=DEFAULT_SEMANTIC_MEMORY.policy_version,
            definitions=(valid,),
        )
    with pytest.raises(SemanticMemoryError, match="source references"):
        replace(valid, source_refs=())
    with pytest.raises(SemanticMemoryError, match="required columns"):
        replace(valid, required_columns=[("customers", "segment")])
    with pytest.raises(SemanticMemoryError, match="required columns"):
        replace(valid, required_columns=())
    with pytest.raises(SemanticMemoryError, match="allowed roles"):
        replace(valid, allowed_roles=())


def test_catalog_rejects_columns_not_present_in_policy(policy):
    """Không cho định nghĩa khai báo cột không tồn tại trong schema của policy tin cậy."""
    invalid_definition = replace(
        DEFAULT_SEMANTIC_MEMORY.definitions[0],
        definition_id="invalid.unknown-column",
        required_columns=(("customers", "made_up_column"),),
    )
    catalog = replace(DEFAULT_SEMANTIC_MEMORY, definitions=(invalid_definition,))

    with pytest.raises(SemanticMemoryError, match="outside the trusted policy"):
        catalog.for_role("sales", policy)


def test_schema_context_narrows_policy_visible_definitions(policy):
    """Schema runtime chỉ có customers.segment thì context cũng chỉ chứa định nghĩa đó."""
    schema = SchemaContext(tables=(SchemaTable("customers", (SchemaColumn("segment", "text"),)),))
    selected = DEFAULT_SEMANTIC_MEMORY.for_role("sales", policy, schema)

    assert {definition.definition_id for definition in selected} == {"customer.segment"}


def test_semantic_definitions_are_immutable_and_have_no_write_api():
    """Agent chỉ đọc catalog; đối tượng và giao diện không cung cấp thao tác ghi/sửa."""
    definition = DEFAULT_SEMANTIC_MEMORY.definitions[0]

    # Dataclass frozen ngăn chỉnh sửa trực tiếp; catalog không có API append/write.
    with pytest.raises(FrozenInstanceError):
        definition.meaning = "modified"
    assert not hasattr(DEFAULT_SEMANTIC_MEMORY, "append")
    assert not hasattr(DEFAULT_SEMANTIC_MEMORY, "write")


def test_definition_rejects_empty_or_malformed_metadata():
    """Kiểm tra định nghĩa lỗi định dạng bị từ chối ngay khi khởi tạo."""
    definition = DEFAULT_SEMANTIC_MEMORY.definitions[0]
    with pytest.raises(SemanticMemoryError, match="ID"):
        replace(definition, definition_id="not a valid id")
    with pytest.raises(SemanticMemoryError, match="column reference"):
        replace(definition, required_columns=(("customers",),))
    with pytest.raises(SemanticMemoryError, match="allowed roles"):
        replace(definition, allowed_roles=("Finance",))
    with pytest.raises(SemanticMemoryError, match="source references"):
        replace(definition, source_refs=("",))


def test_rendered_context_includes_definition_version_and_sources(policy):
    """Planner nhận bản render có version và nguồn để người vận hành truy vết được."""
    rendered = DEFAULT_SEMANTIC_MEMORY.render_for_role("finance", policy)

    assert f"Semantic memory version: {SEMANTIC_MEMORY_VERSION}" in rendered
    assert "[payment.successful-by-paid-date@d2-semantic-v1]" in rendered
    assert "evaluation/README.md#provisional-business" in rendered
