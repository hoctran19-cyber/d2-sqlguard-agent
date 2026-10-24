"""Read-only, role-filtered business definitions for planner context."""

from __future__ import annotations

import re
from dataclasses import dataclass

from sqlguard.agent.schema import SchemaContext
from sqlguard.security.policy import RolePolicy

SEMANTIC_MEMORY_VERSION = "d2-semantic-v1"
POLICY_VERSION = "d2-synthetic-v1"
_IDENTIFIER = re.compile(r"[a-z][a-z0-9_.-]*")
_COLUMN_IDENTIFIER = re.compile(r"[a-z][a-z0-9_]*")
_ROLE_IDENTIFIER = re.compile(r"[a-z][a-z0-9_]*")


class SemanticMemoryError(ValueError):
    """The semantic catalog is invalid or incompatible with the trusted policy."""


@dataclass(frozen=True)
class SemanticDefinition:
    definition_id: str
    version: str
    title: str
    meaning: str
    required_columns: tuple[tuple[str, str], ...]
    allowed_roles: tuple[str, ...]
    source_refs: tuple[str, ...]

    def __post_init__(self) -> None:
        for label, value in (
            ("definition_id", self.definition_id),
            ("version", self.version),
            ("title", self.title),
            ("meaning", self.meaning),
        ):
            if not isinstance(value, str) or not value.strip():
                raise SemanticMemoryError(f"Semantic definition {label} must be non-empty")
        if not _IDENTIFIER.fullmatch(self.definition_id):
            raise SemanticMemoryError("Semantic definition ID is invalid")
        if not isinstance(self.required_columns, tuple) or not self.required_columns:
            raise SemanticMemoryError("Semantic definition must declare required columns")
        for column_ref in self.required_columns:
            if (
                not isinstance(column_ref, tuple)
                or len(column_ref) != 2
                or any(
                    not isinstance(name, str) or not _COLUMN_IDENTIFIER.fullmatch(name)
                    for name in column_ref
                )
            ):
                raise SemanticMemoryError(
                    "Semantic definition contains an invalid column reference"
                )
        if len(set(self.required_columns)) != len(self.required_columns):
            raise SemanticMemoryError("Semantic definition contains duplicate column references")
        if (
            not isinstance(self.allowed_roles, tuple)
            or not self.allowed_roles
            or any(
                not isinstance(role, str)
                or not _ROLE_IDENTIFIER.fullmatch(role)
                or role != role.casefold()
                for role in self.allowed_roles
            )
            or len(set(self.allowed_roles)) != len(self.allowed_roles)
        ):
            raise SemanticMemoryError("Semantic definition contains invalid allowed roles")
        if (
            not isinstance(self.source_refs, tuple)
            or not self.source_refs
            or any(not isinstance(source, str) or not source.strip() for source in self.source_refs)
        ):
            raise SemanticMemoryError("Semantic definition must include source references")


@dataclass(frozen=True)
class SemanticMemory:
    """Immutable catalog; the agent can retrieve definitions but has no write interface."""

    version: str
    policy_version: str
    definitions: tuple[SemanticDefinition, ...]

    def __post_init__(self) -> None:
        if (
            not isinstance(self.version, str)
            or not self.version.strip()
            or not isinstance(self.policy_version, str)
            or not self.policy_version.strip()
        ):
            raise SemanticMemoryError("Semantic memory and policy versions must be non-empty")
        if not isinstance(self.definitions, tuple) or not self.definitions:
            raise SemanticMemoryError("Semantic memory must contain definitions")
        if any(not isinstance(definition, SemanticDefinition) for definition in self.definitions):
            raise SemanticMemoryError("Semantic memory contains an invalid definition")
        ids = [definition.definition_id.casefold() for definition in self.definitions]
        if len(ids) != len(set(ids)):
            raise SemanticMemoryError("Semantic memory contains duplicate definition IDs")
        if any(definition.version != self.version for definition in self.definitions):
            raise SemanticMemoryError("Semantic definition version does not match catalog version")

    def for_role(
        self,
        role: str,
        policy: RolePolicy,
        schema_context: SchemaContext | None = None,
    ) -> tuple[SemanticDefinition, ...]:
        """Return only definitions explicitly allowed and fully readable by the trusted role."""
        if not isinstance(role, str) or not role.strip():
            raise SemanticMemoryError("A trusted role is required for semantic memory")
        trusted_role = role.strip().casefold()
        if not policy.has_role(trusted_role):
            raise SemanticMemoryError("Role is not present in the trusted policy")
        if policy.version != self.policy_version:
            raise SemanticMemoryError("Semantic memory does not match the trusted policy version")
        if any(
            not policy.has_role(allowed_role)
            for definition in self.definitions
            for allowed_role in definition.allowed_roles
        ):
            raise SemanticMemoryError("Semantic definition references a role outside the policy")

        available_columns = None
        if schema_context is not None:
            available_columns = {
                table.name.casefold(): {column.name.casefold() for column in table.columns}
                for table in schema_context.tables
            }

        visible: list[SemanticDefinition] = []
        for definition in self.definitions:
            for table, column in definition.required_columns:
                if column.casefold() not in policy.tables.get(table.casefold(), frozenset()):
                    raise SemanticMemoryError(
                        "Semantic definition references a column outside the trusted policy"
                    )
            if (
                trusted_role in definition.allowed_roles
                and all(
                    policy.can_read(trusted_role, table, column)
                    for table, column in definition.required_columns
                )
                and (
                    available_columns is None
                    or all(
                        column.casefold() in available_columns.get(table.casefold(), set())
                        for table, column in definition.required_columns
                    )
                )
            ):
                visible.append(definition)
        return tuple(visible)

    def render_for_role(
        self,
        role: str,
        policy: RolePolicy,
        schema_context: SchemaContext | None = None,
    ) -> str:
        """Render deterministic, source-linked text for the planner's untrusted-data block."""
        definitions = self.for_role(role, policy, schema_context)
        lines = [f"Semantic memory version: {self.version}"]
        for definition in definitions:
            sources = ", ".join(definition.source_refs)
            lines.append(
                f"- [{definition.definition_id}@{definition.version}] "
                f"{definition.title}: {definition.meaning} Sources: {sources}"
            )
        return "\n".join(lines)


DEFAULT_SEMANTIC_MEMORY = SemanticMemory(
    version=SEMANTIC_MEMORY_VERSION,
    policy_version=POLICY_VERSION,
    definitions=(
        SemanticDefinition(
            "customer.segment",
            SEMANTIC_MEMORY_VERSION,
            "Phân khúc khách hàng",
            "Giá trị phân khúc được tài liệu hóa là retail hoặc enterprise.",
            (("customers", "segment"),),
            ("sales", "finance", "operations"),
            (
                "src/sqlguard/security/policies/d2_synthetic_v1.json#/descriptions/customers/segment",
            ),
        ),
        SemanticDefinition(
            "customer.created-date",
            SEMANTIC_MEMORY_VERSION,
            "Ngày tạo khách hàng",
            "customers.created_at là ngày tạo hồ sơ khách hàng.",
            (("customers", "created_at"),),
            ("sales", "finance", "operations"),
            (
                "src/sqlguard/security/policies/d2_synthetic_v1.json"
                "#/descriptions/customers/created_at",
            ),
        ),
        SemanticDefinition(
            "order.placed-date",
            SEMANTIC_MEMORY_VERSION,
            "Ngày đặt đơn",
            "orders.order_date là ngày đặt đơn; không đồng nhất với ngày thanh toán.",
            (("orders", "order_date"),),
            ("sales", "finance", "operations"),
            (
                "src/sqlguard/security/policies/d2_synthetic_v1.json#/descriptions/orders/order_date",
            ),
        ),
        SemanticDefinition(
            "order.status-values",
            SEMANTIC_MEMORY_VERSION,
            "Trạng thái đơn hàng",
            "Các giá trị được tài liệu hóa là completed, shipped và cancelled.",
            (("orders", "status"),),
            ("sales", "finance", "operations"),
            ("src/sqlguard/security/policies/d2_synthetic_v1.json#/descriptions/orders/status",),
        ),
        SemanticDefinition(
            "order.sales-channel",
            SEMANTIC_MEMORY_VERSION,
            "Kênh bán hàng",
            "Các giá trị kênh được tài liệu hóa là web và store.",
            (("orders", "channel"),),
            ("sales", "finance", "operations"),
            ("src/sqlguard/security/policies/d2_synthetic_v1.json#/descriptions/orders/channel",),
        ),
        SemanticDefinition(
            "order.total-amount-vnd",
            SEMANTIC_MEMORY_VERSION,
            "Tổng tiền đơn hàng",
            "orders.total_amount_vnd là tổng tiền đơn hàng, đơn vị VND.",
            (("orders", "total_amount_vnd"),),
            ("sales", "finance", "operations"),
            (
                "src/sqlguard/security/policies/d2_synthetic_v1.json"
                "#/descriptions/orders/total_amount_vnd",
            ),
        ),
        SemanticDefinition(
            "payment.amount-vnd",
            SEMANTIC_MEMORY_VERSION,
            "Số tiền thanh toán",
            "payments.amount_vnd là số tiền của thanh toán, đơn vị VND.",
            (("payments", "amount_vnd"),),
            ("sales", "finance"),
            (
                "src/sqlguard/security/policies/d2_synthetic_v1.json"
                "#/descriptions/payments/amount_vnd",
            ),
        ),
        SemanticDefinition(
            "payment.successful-by-paid-date",
            SEMANTIC_MEMORY_VERSION,
            "Thanh toán thành công theo kỳ",
            "Theo policy, chỉ tiêu này cộng amount_vnd của payments có status='success', "
            "gom kỳ theo paid_date. Đây là tiền thanh toán thành công, không phải "
            "revenue recognition hay tổng tiền dòng hàng; không cộng payment với transaction.",
            (("payments", "amount_vnd"), ("payments", "status"), ("payments", "paid_date")),
            ("sales", "finance"),
            (
                "src/sqlguard/security/policies/d2_synthetic_v1.json#/descriptions/payments/_table",
                "evaluation/README.md#provisional-business",
            ),
        ),
        SemanticDefinition(
            "order-item.sale-quantity-and-price",
            SEMANTIC_MEMORY_VERSION,
            "Số lượng và đơn giá bán",
            "order_items.quantity là số lượng; order_items.unit_price_vnd là đơn giá bán "
            "mỗi đơn vị, tính bằng VND. Catalog không định nghĩa thêm công thức tổng dòng.",
            (("order_items", "quantity"), ("order_items", "unit_price_vnd")),
            ("sales", "finance", "operations"),
            (
                "src/sqlguard/security/policies/d2_synthetic_v1.json"
                "#/descriptions/order_items/quantity",
                "src/sqlguard/security/policies/d2_synthetic_v1.json"
                "#/descriptions/order_items/unit_price_vnd",
            ),
        ),
        SemanticDefinition(
            "product.list-price-vnd",
            SEMANTIC_MEMORY_VERSION,
            "Giá niêm yết sản phẩm",
            "products.list_price_vnd là giá niêm yết của sản phẩm, tính bằng VND.",
            (("products", "list_price_vnd"),),
            ("sales", "finance", "operations"),
            (
                "src/sqlguard/security/policies/d2_synthetic_v1.json"
                "#/descriptions/products/list_price_vnd",
            ),
        ),
        SemanticDefinition(
            "order-item.unit-cost-finance",
            SEMANTIC_MEMORY_VERSION,
            "Giá vốn mỗi đơn vị",
            "order_items.unit_cost_vnd là giá vốn cho mỗi đơn vị; chỉ đưa định nghĩa này "
            "vào context Finance vì policy chỉ cấp cột này cho Finance.",
            (("order_items", "unit_cost_vnd"),),
            ("finance",),
            (
                "src/sqlguard/security/policies/d2_synthetic_v1.json#/roles/finance/order_items",
                "src/sqlguard/security/policies/d2_synthetic_v1.json"
                "#/descriptions/order_items/unit_cost_vnd",
            ),
        ),
        SemanticDefinition(
            "order.customer-link",
            SEMANTIC_MEMORY_VERSION,
            "Liên kết đơn hàng với khách hàng",
            "orders.customer_id tham chiếu customers.customer_id để liên kết đơn hàng "
            "với khách hàng.",
            (("orders", "customer_id"), ("customers", "customer_id")),
            ("sales", "finance", "operations"),
            ("src/sqlguard/security/policies/d2_synthetic_v1.json#/foreign_keys/0",),
        ),
    ),
)

BUSINESS_SEMANTIC_MEMORY_VERSION = "business-semantic-v1"
BUSINESS_POLICY_VERSION = "business-financial-v1"
_BUSINESS_POLICY_FILE = "src/sqlguard/security/policies/business_financial_v1.json"
_ALL_BUSINESS_ROLES = ("operator", "analyst", "credit_officer")


def _business(definition_id, title, meaning, columns, roles):
    sources = tuple(
        f"{_BUSINESS_POLICY_FILE}#/descriptions/{table}/{column}" for table, column in columns
    )
    return SemanticDefinition(
        definition_id, BUSINESS_SEMANTIC_MEMORY_VERSION, title, meaning, columns, roles, sources
    )


BUSINESS_SEMANTIC_MEMORY = SemanticMemory(
    version=BUSINESS_SEMANTIC_MEMORY_VERSION,
    policy_version=BUSINESS_POLICY_VERSION,
    definitions=(
        _business(
            "trans.type-codes",
            "Chiều tiền của giao dịch",
            "trans.type = 'PRIJEM' là tiền vào, 'VYDAJ' là tiền ra; amount luôn dương, nên "
            "dòng tiền ròng phải tách theo type.",
            (("trans", "type"), ("trans", "amount")),
            _ALL_BUSINESS_ROLES,
        ),
        _business(
            "trans.k-symbol",
            "Mục đích giao dịch",
            "trans.k_symbol phân loại mục đích, ví dụ 'UVER' là trả nợ vay, 'SIPO' là sinh hoạt, "
            "'DUCHOD' là lương hưu, 'UROK' là lãi; có thể rỗng.",
            (("trans", "k_symbol"),),
            _ALL_BUSINESS_ROLES,
        ),
        _business(
            "trans.balance-after",
            "Số dư sau giao dịch",
            "trans.balance là số dư lịch sử ngay sau giao dịch đó, không phải số dư hiện tại "
            "của tài khoản.",
            (("trans", "balance"),),
            ("operator", "credit_officer"),
        ),
        _business(
            "account.frequency-codes",
            "Tần suất sao kê",
            "account.frequency: 'POPLATEK MESICNE' hằng tháng, 'POPLATEK TYDNE' hằng tuần, "
            "'POPLATEK PO OBRATU' sau mỗi giao dịch.",
            (("account", "frequency"),),
            _ALL_BUSINESS_ROLES,
        ),
        _business(
            "disp.owner",
            "Chủ tài khoản",
            "disp nối client với account; disp.type = 'OWNER' là chủ tài khoản, 'DISPONENT' là "
            "người được ủy quyền. Khi cần đúng một khách hàng cho mỗi tài khoản, thêm "
            "disp.type = 'OWNER' vào WHERE (không đặt trong ON).",
            (("disp", "type"), ("disp", "client_id"), ("disp", "account_id")),
            _ALL_BUSINESS_ROLES,
        ),
        _business(
            "district.region",
            "Vùng và quận",
            "district.a2 là tên quận, district.a3 là vùng; account.district_id là quận của chi "
            "nhánh, client.district_id là quận của khách hàng.",
            (("district", "a2"), ("district", "a3"), ("account", "district_id")),
            _ALL_BUSINESS_ROLES,
        ),
        _business(
            "district.average-salary",
            "Lương trung bình vùng",
            "district.a11 là lương trung bình của quận, không phải thu nhập của khách hàng; "
            "a12/a13 là tỷ lệ thất nghiệp 1995/1996.",
            (("district", "a11"), ("district", "a12"), ("district", "a13")),
            ("analyst", "credit_officer"),
        ),
        _business(
            "analyst.distinct-clients",
            "Đếm khách hàng và tài khoản",
            "Đếm khách hàng bằng COUNT(DISTINCT client.client_id) và tài khoản bằng "
            "COUNT(DISTINCT account.account_id); không xuất danh sách ID.",
            (("client", "client_id"), ("account", "account_id")),
            ("analyst",),
        ),
        _business(
            "loan.status-codes",
            "Trạng thái khoản vay",
            "loan.status: 'A' đã kết thúc, không vấn đề; 'B' đã kết thúc, chưa trả; 'C' đang "
            "chạy, ổn; 'D' đang chạy, khách đang nợ. B và D là khoản vay cần theo dõi.",
            (("loan", "status"),),
            ("credit_officer",),
        ),
        _business(
            "loan.amount-original",
            "Số tiền vay",
            "loan.amount là vốn vay ban đầu, không phải dư nợ hiện tại; loan.payments là số "
            "tiền trả hằng tháng, loan.duration là thời hạn theo tháng.",
            (("loan", "amount"), ("loan", "payments"), ("loan", "duration")),
            ("credit_officer",),
        ),
        _business(
            "order.standing-order",
            "Lệnh thanh toán định kỳ",
            "order là lệnh chuyển tiền định kỳ; một lệnh không chứng minh tiền đã chuyển thành "
            "công. order.k_symbol = 'UVER' là lệnh trả nợ vay.",
            (("order", "amount"), ("order", "k_symbol")),
            ("operator", "credit_officer"),
        ),
    ),
)

_CATALOGS = {
    catalog.policy_version: catalog
    for catalog in (DEFAULT_SEMANTIC_MEMORY, BUSINESS_SEMANTIC_MEMORY)
}


def semantic_memory_for(policy: RolePolicy) -> SemanticMemory | None:
    """The reviewed catalog written for this policy version, if any."""
    return _CATALOGS.get(policy.version)
