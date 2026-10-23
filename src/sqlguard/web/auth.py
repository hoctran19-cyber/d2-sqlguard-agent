"""Đăng nhập demo và quản lý session trong bộ nhớ.

Chỉ dùng cho demo local: tài khoản cố định theo UI.md, session mất khi restart server.
Khi nhóm chốt role theo nghiệp vụ (B), thay bảng DEMO_USERS bằng users store thật.
"""

from __future__ import annotations

import hmac
import secrets
import time
from dataclasses import dataclass

SESSION_COOKIE = "sqlguard_session"
SESSION_TTL_SECONDS = 8 * 60 * 60  # Session sống tối đa 8 giờ.


@dataclass(frozen=True)
class User:
    # "admin": xem toàn bộ dữ liệu; "evaluator": chỉ dùng trang Evaluation;
    # BUSINESS_ROLES: vào /home, xem Info tham chiếu, truy vấn dữ liệu bị tắt.
    username: str
    role: str
    home: str  # Trang được chuyển tới sau khi đăng nhập.


ADMIN_ROLE = "admin"
EVALUATOR_ROLE = "evaluator"
# Keep these identifiers distinct from the teller/credit/risk roles in bird_financial_v1.
# No reviewed policy crosswalk exists, so recognizing a login does not grant query access.
BUSINESS_ROLES = ("operator", "analyst", "credit_officer")
KNOWN_ROLES = frozenset({ADMIN_ROLE, EVALUATOR_ROLE, *BUSINESS_ROLES})


def is_known_role(role: object) -> bool:
    """Accept only the server-defined, canonical role identifiers."""
    return isinstance(role, str) and role in KNOWN_ROLES


ROLE_LABELS = {
    ADMIN_ROLE: "Admin — quản trị demo",
    EVALUATOR_ROLE: "Evaluator — chỉ dùng trang Evaluation",
    "operator": "Operator — chuyên viên vận hành và hỗ trợ người dùng",
    "analyst": "Analyst — chuyên viên phân tích và tổng hợp",
    "credit_officer": "Credit Officer — chuyên viên quản trị dư nợ và tín dụng",
}

# Tài khoản demo theo UI.md. Mật khẩu chỉ để chạy local, KHÔNG dùng cho môi trường thật.
# Role gắn cố định với username; client không thể tự khai role khi đăng nhập.
DEMO_USERS = {
    "admin": ("123456", User("admin", ADMIN_ROLE, "/home")),
    "eval": ("123456", User("eval", EVALUATOR_ROLE, "/evaluation/")),
    "operator": ("123456", User("operator", "operator", "/home")),
    "analyst": ("123456", User("analyst", "analyst", "/home")),
    "credit": ("123456", User("credit", "credit_officer", "/home")),
}


def authenticate(username: str, password: str) -> User | None:
    """Trả về User nếu đúng tài khoản/mật khẩu, ngược lại trả None."""
    entry = DEMO_USERS.get(username)
    # Luôn so sánh (kể cả khi sai username) để thời gian phản hồi không lộ username tồn tại.
    expected = entry[0] if entry else "x" * len(password or "x")
    matched = hmac.compare_digest(expected.encode(), (password or "").encode())
    return entry[1] if entry and matched else None


class SessionStore:
    """Lưu session token -> (user, thời điểm hết hạn) trong bộ nhớ của process."""

    def __init__(self) -> None:
        self._sessions: dict[str, tuple[User, float]] = {}

    def create(self, user: User) -> str:
        if not isinstance(user, User) or not is_known_role(user.role):
            raise ValueError("Cannot create a session for an unknown role")
        token = secrets.token_urlsafe(32)  # Token ngẫu nhiên, khó đoán.
        self._sessions[token] = (user, time.monotonic() + SESSION_TTL_SECONDS)
        return token

    def get(self, token: str | None) -> User | None:
        if not token:
            return None
        entry = self._sessions.get(token)
        if entry is None:
            return None
        user, expires_at = entry
        if not isinstance(user, User) or not is_known_role(user.role):
            self._sessions.pop(token, None)
            return None
        if time.monotonic() >= expires_at:  # Hết hạn thì xóa luôn.
            self._sessions.pop(token, None)
            return None
        return user

    def delete(self, token: str | None) -> None:
        if token:
            self._sessions.pop(token, None)
