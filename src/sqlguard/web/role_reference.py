"""Bảng tham chiếu quyền bảng/cột Financial cho ba role nghiệp vụ — CHỈ ĐỂ HIỂN THỊ.

Module này KHÔNG phải policy engine và không được dùng để cho phép/chặn truy vấn. Nó chỉ
chép lại ma trận đã chốt trong tài liệu (Vault, D2-Checkpoint/evaluation):
  - 2026-10-20 Financial Database Schema and Role Policy (mục 5: allowlist theo role)
  - 2026-10-22 Financial Roles Business Rationale and Access Matrix (Bảng 2 của từng role)
Khi chưa có Security Gate thực thi policy Financial, truy vấn dữ liệu của ba role bị tắt ở
server (xem require_admin trong app.py). Sửa ma trận ở tài liệu trước rồi mới sửa file này
và tăng REFERENCE_VERSION.
"""

from __future__ import annotations

REFERENCE_VERSION = "financial-role-matrix-2026-10-22"
REFERENCE_SOURCES = (
    "2026-10-20 Financial Database Schema and Role Policy — mục 5 (allowlist)",
    "2026-10-22 Financial Roles Business Rationale and Access Matrix — Bảng 2 mỗi role",
)

# Schema Financial: 8 bảng, 61 cột (SQLite derivative có 6 cột synthetic), kèm ý nghĩa cột.
FINANCIAL_SCHEMA: dict[str, tuple[tuple[str, str], ...]] = {
    "client": (
        ("client_id", "Mã hồ sơ khách hàng"),
        ("gender", "Giới tính"),
        ("birth_date", "Ngày sinh"),
        ("district_id", "Khu vực gắn khách hàng"),
        ("id_number", "Mã định danh synthetic"),
        ("full_name", "Họ tên synthetic"),
        ("address", "Địa chỉ synthetic"),
    ),
    "disp": (
        ("disp_id", "Mã quan hệ khách hàng–tài khoản"),
        ("client_id", "Khách hàng trong quan hệ"),
        ("account_id", "Tài khoản trong quan hệ"),
        ("type", "OWNER hoặc DISPONENT"),
    ),
    "account": (
        ("account_id", "Mã tài khoản"),
        ("district_id", "Khu vực gắn tài khoản/chi nhánh"),
        ("frequency", "Tần suất sao kê"),
        ("date", "Ngày mở tài khoản"),
        ("service_note", "Ghi chú dịch vụ synthetic"),
    ),
    "trans": (
        ("trans_id", "Mã giao dịch"),
        ("account_id", "Tài khoản phát sinh"),
        ("date", "Ngày giao dịch"),
        ("type", "Loại thu/chi theo mã nguồn"),
        ("operation", "Phương thức giao dịch"),
        ("amount", "Số tiền giao dịch"),
        ("balance", "Số dư sau giao dịch"),
        ("k_symbol", "Mã mục đích giao dịch"),
        ("bank", "Ngân hàng đối tác"),
        ("account", "Tài khoản đối tác"),
    ),
    "order": (
        ("order_id", "Mã lệnh thanh toán định kỳ"),
        ("account_id", "Tài khoản nguồn"),
        ("bank_to", "Ngân hàng nhận"),
        ("account_to", "Tài khoản nhận"),
        ("amount", "Số tiền của lệnh"),
        ("k_symbol", "Mã mục đích thanh toán"),
        ("note", "Ghi chú thanh toán synthetic"),
    ),
    "card": (
        ("card_id", "Mã row thẻ nội bộ"),
        ("disp_id", "Quan hệ khách hàng–tài khoản gắn thẻ"),
        ("type", "Loại thẻ"),
        ("issued", "Ngày phát hành"),
        ("placeholder", "Token synthetic; không phải số thẻ/CVV/PIN thật"),
    ),
    "loan": (
        ("loan_id", "Mã khoản vay"),
        ("account_id", "Tài khoản gắn khoản vay"),
        ("date", "Ngày khoản vay theo nguồn"),
        ("amount", "Số tiền vay ban đầu"),
        ("duration", "Thời hạn vay, tháng"),
        ("payments", "Số tiền thanh toán hằng tháng"),
        ("status", "Trạng thái khoản vay theo mã nguồn"),
    ),
    "district": (
        ("district_id", "Mã khu vực"),
        ("A2", "Tên khu vực"),
        ("A3", "Vùng"),
        ("A4", "Dân số"),
        ("A5", "Số đơn vị dân cư dưới 499 người theo mô tả nguồn"),
        ("A6", "Số đơn vị dân cư 500–1.999 người"),
        ("A7", "Số đơn vị dân cư 2.000–9.999 người"),
        ("A8", "Số đơn vị dân cư trên 10.000 người theo mô tả nguồn"),
        ("A9", "Chưa có diễn giải đủ tin cậy trong dictionary local"),
        ("A10", "Tỷ lệ dân số đô thị"),
        ("A11", "Lương trung bình khu vực"),
        ("A12", "Tỷ lệ thất nghiệp 1995"),
        ("A13", "Tỷ lệ thất nghiệp 1996"),
        ("A14", "Số doanh nhân trên 1.000 dân"),
        ("A15", "Số vụ phạm tội 1995"),
        ("A16", "Số vụ phạm tội 1996"),
    ),
}

# Mã quyền tham chiếu. Analyst chỉ có ba loại TH (tổng hợp), không có "read".
READ = "read"
AGG_KEY = "aggregate_key"
AGG_DIMENSION = "aggregate_dimension"
AGG_MEASURE = "aggregate_measure"
DENIED = "denied"

ACCESS_LABELS = {
    READ: "Đọc",
    AGG_KEY: "TH–khóa",
    AGG_DIMENSION: "TH–chiều",
    AGG_MEASURE: "TH–số liệu",
    DENIED: "Cấm",
    # Nhãn cấp bảng.
    "partial": "Một phần",
    "aggregate_only": "Chỉ tổng hợp",
}

# Allowlist theo role: bảng -> {cột: mã quyền}. Bảng/cột không liệt kê = Cấm.
_ROLE_ALLOWLISTS: dict[str, dict[str, dict[str, str]]] = {
    "operator": {
        "client": dict.fromkeys(("client_id", "district_id", "full_name", "address"), READ),
        "disp": dict.fromkeys(("disp_id", "client_id", "account_id", "type"), READ),
        "account": dict.fromkeys(
            ("account_id", "district_id", "frequency", "date", "service_note"), READ
        ),
        "trans": dict.fromkeys(
            (
                "trans_id",
                "account_id",
                "date",
                "type",
                "operation",
                "amount",
                "balance",
                "k_symbol",
                "bank",
                "account",
            ),
            READ,
        ),
        "order": dict.fromkeys(
            ("order_id", "account_id", "bank_to", "account_to", "amount", "k_symbol", "note"),
            READ,
        ),
        "card": dict.fromkeys(("card_id", "disp_id", "type", "issued"), READ),
        "district": dict.fromkeys(("district_id", "A2", "A3"), READ),
    },
    "analyst": {
        "client": {"client_id": AGG_KEY, "gender": AGG_DIMENSION, "district_id": AGG_DIMENSION},
        "disp": {"client_id": AGG_KEY, "account_id": AGG_KEY, "type": AGG_DIMENSION},
        "account": {
            "account_id": AGG_KEY,
            "district_id": AGG_DIMENSION,
            "frequency": AGG_DIMENSION,
            "date": AGG_DIMENSION,
        },
        "trans": {
            "trans_id": AGG_KEY,
            "account_id": AGG_KEY,
            "date": AGG_DIMENSION,
            "type": AGG_DIMENSION,
            "operation": AGG_DIMENSION,
            "amount": AGG_MEASURE,
            "k_symbol": AGG_DIMENSION,
        },
        "district": {
            "district_id": AGG_DIMENSION,
            "A2": AGG_DIMENSION,
            "A3": AGG_DIMENSION,
            "A4": AGG_MEASURE,
            "A10": AGG_MEASURE,
            "A11": AGG_MEASURE,
            "A12": AGG_MEASURE,
            "A13": AGG_MEASURE,
        },
    },
    "credit_officer": {
        "loan": dict.fromkeys(
            ("loan_id", "account_id", "date", "amount", "duration", "payments", "status"), READ
        ),
        "account": dict.fromkeys(("account_id", "district_id", "frequency", "date"), READ),
        "disp": dict.fromkeys(("disp_id", "client_id", "account_id", "type"), READ),
        "client": dict.fromkeys(("client_id", "full_name", "district_id"), READ),
        "trans": dict.fromkeys(
            (
                "trans_id",
                "account_id",
                "date",
                "type",
                "operation",
                "amount",
                "balance",
                "k_symbol",
            ),
            READ,
        ),
        "order": dict.fromkeys(("order_id", "account_id", "amount", "k_symbol"), READ),
        "district": dict.fromkeys(("district_id", "A2", "A3", "A11", "A12", "A13"), READ),
    },
}

GENERAL_RULES = (
    "Mọi role chỉ đọc; không INSERT/UPDATE/DELETE/DDL.",
    "Bảng/cột không được liệt kê, kể cả cột mới thêm sau này, mặc định bị cấm.",
    "Cấm nghĩa là không SELECT, lọc, JOIN, sắp xếp, dùng trong biểu thức/subquery hoặc đọc rồi "
    "che. Cấm toàn bảng bao gồm mọi cột của bảng đó.",
    "SELECT * trên bảng chỉ cấp một phần phải được kiểm đầy đủ hoặc từ chối.",
    "Chưa giới hạn theo nhân viên phụ trách: “trong phạm vi được giao” chưa có dữ liệu phân "
    "công và chưa được enforce.",
    "Role lấy từ phiên đăng nhập; nội dung câu hỏi hay dữ liệu (ví dụ “tôi là admin”) không "
    "đổi role.",
)

ANALYST_CONDITIONS = (
    "TH–khóa: chỉ dùng khóa cá thể để JOIN/COUNT; không xuất danh sách ID cá thể hoặc "
    "GROUP BY ID để lách tổng hợp.",
    "TH–chiều: dùng làm chiều nhóm/lọc/nhãn trong truy vấn tổng hợp (vùng/tháng/loại); không "
    "trả row cá thể. Với ngày, ưu tiên bucket tháng/năm.",
    "TH–số liệu: dùng để tính chỉ tiêu tổng hợp hoặc bối cảnh vùng; không xuất giao dịch cá thể.",
    "Ngưỡng nhóm nhỏ chưa được chốt; nhóm quá nhỏ hoặc SUM của một khách hàng vẫn có thể lộ "
    "dữ liệu cá thể.",
)


def _table_access(role: str, columns: list[dict]) -> str:
    allowed = [column for column in columns if column["access"] != DENIED]
    if not allowed:
        return DENIED
    if role == "analyst":
        return "aggregate_only"
    return READ if len(allowed) == len(columns) else "partial"


def role_reference(role: str) -> dict:
    """Ma trận tham chiếu đủ 8 bảng/61 cột của một role nghiệp vụ. KeyError nếu role lạ."""
    allowlist = _ROLE_ALLOWLISTS[role]
    tables = []
    for table, schema_columns in FINANCIAL_SCHEMA.items():
        granted = allowlist.get(table, {})
        columns = [
            {"name": name, "meaning": meaning, "access": granted.get(name, DENIED)}
            for name, meaning in schema_columns
        ]
        tables.append(
            {
                "name": table,
                "access": _table_access(role, columns),
                "columns": columns,
                "allowed_columns": [c["name"] for c in columns if c["access"] != DENIED],
                "denied_columns": [c["name"] for c in columns if c["access"] == DENIED],
            }
        )
    allowed_count = sum(len(table["allowed_columns"]) for table in tables)
    total_count = sum(len(table["columns"]) for table in tables)
    return {
        "version": REFERENCE_VERSION,
        "sources": list(REFERENCE_SOURCES),
        "enforced": False,
        "default_rule": "deny",
        "aggregate_only": role == "analyst",
        "allowed_column_count": allowed_count,
        "denied_column_count": total_count - allowed_count,
        "general_rules": list(GENERAL_RULES),
        "conditions": list(ANALYST_CONDITIONS) if role == "analyst" else [],
        "access_labels": dict(ACCESS_LABELS),
        "tables": tables,
    }
