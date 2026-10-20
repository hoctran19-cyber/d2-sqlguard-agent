"""Planner DEMO cho trang Query khi chưa có LLM (phần của A — Agent Runtime).

Planner này KHÔNG hiểu ngôn ngữ tự nhiên: nó chỉ tra một bảng câu hỏi mẫu cố định -> SQL.
Mục đích duy nhất là để chạy thử giao diện qua đúng đường Controller -> Gate -> Database.
Không được dùng kết quả của planner này như kết quả đánh giá LLM.
"""

from __future__ import annotations

import re

from sqlguard.agent.planning import Plan

PLANNER_NAME = "demo-no-llm"

# Câu hỏi mẫu -> SQL trên database financial. Câu cuối cố tình sinh lệnh ghi
# để minh họa trường hợp Security Gate từ chối (database không bao giờ nhận lệnh này).
SAMPLE_QUESTIONS: dict[str, str] = {
    "Có bao nhiêu khách hàng trong hệ thống?": "SELECT COUNT(*) AS client_count FROM client",
    "Liệt kê 10 khoản vay có số tiền lớn nhất.": (
        "SELECT loan_id, account_id, date, amount, duration, status "
        "FROM loan ORDER BY amount DESC LIMIT 10"
    ),
    "Số lượng tài khoản theo tần suất sao kê là bao nhiêu?": (
        "SELECT frequency, COUNT(*) AS account_count "
        "FROM account GROUP BY frequency ORDER BY account_count DESC"
    ),
    "Mỗi loại thẻ có bao nhiêu thẻ?": (
        "SELECT type, COUNT(*) AS card_count FROM card GROUP BY type ORDER BY card_count DESC"
    ),
    "Liệt kê các giao dịch của tài khoản 1.": (
        "SELECT trans_id, date, type, operation, amount, balance "
        "FROM trans WHERE account_id = 1 ORDER BY date, trans_id"
    ),
    "Xóa toàn bộ dữ liệu khoản vay.": "DELETE FROM loan",
}


def _normalize(text: str) -> str:
    """Chuẩn hóa để so khớp: chữ thường, gộp khoảng trắng, bỏ dấu câu ở cuối."""
    return re.sub(r"\s+", " ", text).strip().rstrip(".?!").strip().casefold()


_LOOKUP = {_normalize(question): sql for question, sql in SAMPLE_QUESTIONS.items()}


class DemoFinancialPlanner:
    """Cài đặt Planner protocol của Controller bằng bảng tra cứu câu hỏi mẫu."""

    def __init__(self) -> None:
        self.last_sql: str | None = None  # Lưu lại SQL đã sinh để UI hiển thị.

    def supports(self, question: str) -> bool:
        return _normalize(question) in _LOOKUP

    async def create_plan(self, question: str, context: tuple[str, ...]) -> Plan:
        del context  # Planner demo không dùng memory/context.
        sql = _LOOKUP.get(_normalize(question))
        if sql is None:
            raise LookupError("Planner demo chỉ hỗ trợ các câu hỏi mẫu")
        self.last_sql = sql
        return Plan(sql=sql, summary="Demo planner: tra bảng câu hỏi mẫu, không gọi LLM")
