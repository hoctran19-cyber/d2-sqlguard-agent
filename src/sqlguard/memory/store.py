from __future__ import annotations

import math
from collections.abc import Callable
from dataclasses import dataclass, field
from time import monotonic
from typing import Protocol


class MemoryStore(Protocol):
    def append(self, run_id: str, kind: str, value: str) -> None: ...

    def get(self, run_id: str, kind: str | None = None) -> tuple[str, ...]: ...


@dataclass
class InMemoryMemory:
    """Bộ nhớ ngắn hạn trong tiến trình, phân vùng riêng theo từng ``run_id``.

    TTL được tính từ lần ghi gần nhất của mỗi run; việc ghi thêm vào một run sẽ gia hạn
    thời gian sống cho toàn bộ dữ liệu của run đó. Dữ liệu hết hạn được dọn trong các thao
    tác đọc/ghi kế tiếp hoặc có thể dọn chủ động bằng ``cleanup_expired``.
    """

    # Nội dung được lưu theo run_id, mỗi phần tử giữ nguyên cặp loại dữ liệu và giá trị để
    # tương thích với giao diện append/get hiện tại.
    _entries: dict[str, list[tuple[str, str]]] = field(default_factory=dict)
    # Thời gian sống tối đa tính bằng giây; mặc định giữ dữ liệu trong một giờ.
    ttl_seconds: float = 3600
    # Đồng hồ đơn điệu tránh sai lệch khi giờ hệ thống thay đổi; cho phép tiêm đồng hồ giả
    # để kiểm thử TTL mà không cần chờ thời gian thực.
    clock: Callable[[], float] = field(default=monotonic, repr=False)
    # Thời điểm hết hạn riêng cho mỗi run_id, tính bằng clock() + ttl_seconds.
    _expires_at: dict[str, float] = field(default_factory=dict, repr=False)

    def __post_init__(self) -> None:
        # TTL bằng 0, âm, vô cực hoặc NaN khiến quy tắc hết hạn không có ý nghĩa ổn định.
        if not math.isfinite(self.ttl_seconds) or self.ttl_seconds <= 0:
            raise ValueError("Memory TTL must be a positive finite number")

    def append(self, run_id: str, kind: str, value: str) -> None:
        now = self.clock()
        # Dọn dữ liệu cũ trước khi thêm để bộ nhớ không giữ những run đã hết hạn khi có ghi mới.
        self.cleanup_expired(now)
        self._entries.setdefault(run_id, []).append((kind, value))
        # Gia hạn hạn dùng của toàn bộ dữ liệu trong run theo lần ghi gần nhất.
        self._expires_at[run_id] = now + self.ttl_seconds

    def get(self, run_id: str, kind: str | None = None) -> tuple[str, ...]:
        # Dọn trước khi đọc để không trả lại dữ liệu hết hạn, kể cả khi run không có ghi mới.
        self.cleanup_expired()
        return tuple(
            value
            for entry_kind, value in self._entries.get(run_id, ())
            if kind is None or entry_kind == kind
        )

    def cleanup_expired(self, now: float | None = None) -> int:
        """Dọn dữ liệu đã hết TTL và trả về số run đã bị xóa.

        Tham số ``now`` dùng cho kiểm thử hoặc trường hợp bên gọi đã có mốc giờ từ clock;
        nếu bỏ qua, phương thức tự lấy thời gian từ clock đã cấu hình trên đối tượng.
        """
        current_time = self.clock() if now is None else now
        # Thu thập khóa trước khi xóa để tránh thay đổi dictionary trong lúc đang duyệt.
        expired = [run_id for run_id, expiry in self._expires_at.items() if expiry <= current_time]
        for run_id in expired:
            # Xóa đồng thời nội dung và thời điểm hết hạn để hai bảng trạng thái luôn nhất quán.
            del self._entries[run_id]
            del self._expires_at[run_id]
        return len(expired)
