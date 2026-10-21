"""Đọc database BIRD Mini-Dev "financial" (SQLite) ở chế độ chỉ đọc, có phân trang.

Lớp này KHÔNG kiểm tra quyền: mọi câu SQL phải qua Security Gate trước khi gọi run_page.
"""

from __future__ import annotations

import os
import sqlite3
import time
from dataclasses import dataclass
from pathlib import Path

import sqlglot

PAGE_SIZE = 20  # UI.md: mỗi trang 20 dòng.
DEFAULT_TIMEOUT_SECONDS = 3.0  # Giống giới hạn query timeout trong ExecutionBudget.
DB_ENV = "SQLGUARD_FINANCIAL_DB"
# Nếu không đặt biến môi trường thì tìm file ở thư mục data/bird/ (đã được .gitignore).
DEFAULT_DB_PATH = Path(__file__).resolve().parents[3] / "data" / "bird" / "financial.sqlite"


class DatabaseUnavailable(Exception):
    """Chưa cấu hình hoặc không tìm thấy file database."""


class QueryTimeout(Exception):
    """Truy vấn chạy quá thời gian cho phép và đã bị ngắt."""


class QueryError(Exception):
    """SQLite báo lỗi khi chạy câu SQL (sai tên cột, sai cú pháp SQLite, ...)."""


@dataclass(frozen=True)
class PageResult:
    sql: str  # Câu SQL đã chuẩn hóa (một câu duy nhất).
    columns: list[str]
    rows: list[list]
    page: int
    page_size: int
    total_rows: int
    total_pages: int

    def to_dict(self) -> dict:
        return {
            "sql": self.sql,
            "columns": self.columns,
            "rows": self.rows,
            "page": self.page,
            "page_size": self.page_size,
            "total_rows": self.total_rows,
            "total_pages": self.total_pages,
        }


def resolve_db_path() -> Path:
    """Ưu tiên biến môi trường SQLGUARD_FINANCIAL_DB, sau đó tới data/bird/financial.sqlite."""
    configured = os.environ.get(DB_ENV)
    return Path(configured).expanduser() if configured else DEFAULT_DB_PATH


class FinancialDatabase:
    def __init__(self, path: Path) -> None:
        self.path = Path(path)

    def _connect(self) -> sqlite3.Connection:
        if not self.path.is_file():
            raise DatabaseUnavailable(f"Không tìm thấy database financial: đặt biến {DB_ENV}")
        # mode=ro: mở file chỉ đọc; query_only: chặn thêm mọi lệnh ghi ở tầng SQLite.
        connection = sqlite3.connect(f"{self.path.resolve().as_uri()}?mode=ro", uri=True)
        connection.execute("PRAGMA query_only = ON")
        return connection

    def table_names(self) -> list[str]:
        """Danh sách bảng nghiệp vụ (bỏ bảng nội bộ sqlite_*)."""
        connection = self._connect()
        try:
            rows = connection.execute(
                "SELECT name FROM sqlite_master WHERE type = 'table' "
                "AND name NOT LIKE 'sqlite_%' ORDER BY name"
            ).fetchall()
            return [name for (name,) in rows]
        finally:
            connection.close()

    def table_columns(self) -> dict[str, list[str]]:
        """Bảng -> danh sách cột, dùng cho popup Info."""
        connection = self._connect()
        try:
            result = {}
            for table in self.table_names():
                quoted = table.replace('"', '""')
                info = connection.execute(f'PRAGMA table_info("{quoted}")').fetchall()
                result[table] = [column[1] for column in info]
            return result
        finally:
            connection.close()

    def run_page(
        self, sql: str, *, page: int = 1, timeout_seconds: float = DEFAULT_TIMEOUT_SECONDS
    ) -> PageResult:
        """Chạy một câu SELECT đã được Gate cho phép, trả về đúng một trang dữ liệu."""
        # Chuẩn hóa lại bằng sqlglot: bỏ dấu ';' thừa và chắc chắn chỉ còn một câu lệnh.
        inner = sqlglot.parse_one(sql, read="sqlite").sql(dialect="sqlite")
        page = max(1, int(page))
        connection = self._connect()
        deadline = time.monotonic() + timeout_seconds
        # SQLite gọi hàm này định kỳ; trả về 1 nghĩa là ngắt truy vấn đang chạy.
        connection.set_progress_handler(lambda: 1 if time.monotonic() > deadline else 0, 10_000)
        try:
            # Đếm tổng số dòng để tính số trang, rồi lấy đúng trang được yêu cầu.
            (total_rows,) = connection.execute(f"SELECT COUNT(*) FROM ({inner})").fetchone()
            total_pages = max(1, -(-total_rows // PAGE_SIZE))  # Làm tròn lên.
            page = min(page, total_pages)
            cursor = connection.execute(
                f"SELECT * FROM ({inner}) LIMIT ? OFFSET ?",
                (PAGE_SIZE, (page - 1) * PAGE_SIZE),
            )
            columns = [description[0] for description in cursor.description]
            rows = [[_json_cell(value) for value in row] for row in cursor.fetchall()]
        except sqlite3.OperationalError as error:
            if "interrupted" in str(error):
                raise QueryTimeout(f"Truy vấn vượt quá {timeout_seconds:g} giây") from None
            raise QueryError(str(error)) from None
        except sqlite3.DatabaseError as error:
            raise QueryError(str(error)) from None
        finally:
            connection.close()
        return PageResult(inner, columns, rows, page, PAGE_SIZE, total_rows, total_pages)


def _json_cell(value):
    """Chuyển giá trị SQLite sang kiểu gửi được qua JSON (bytes -> chuỗi hex)."""
    return value.hex() if isinstance(value, bytes) else value
