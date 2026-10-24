"""Web-side plumbing for the Attack Lab: run guard, error mapping and run revisions.

The lab service itself lives in ``sqlguard.security.attack_lab``. This module only decides how the
web process coordinates it with business queries and how lab errors look over HTTP. Error texts are
generic on purpose: no SQLite message, path or payload ever reaches the client.
"""

from __future__ import annotations

import asyncio
from collections.abc import AsyncIterator
from contextlib import asynccontextmanager

from sqlguard.security.attack_lab import AttackLab, LabError

# category -> (HTTP status, message), see docs/threat-model/ATTACK_LAB.md section 3.
LAB_ERRORS: dict[str, tuple[int, str]] = {
    "lab_disabled": (404, "Attack Lab đang tắt."),
    "target_not_allowed": (404, "Không có target này trong Attack Lab."),
    "run_active": (409, "Đang có lần chạy truy vấn; thử lại sau khi nó kết thúc."),
    "revision_conflict": (409, "Note đã đổi revision; tải lại rồi thử lại."),
    "invalid_payload": (422, "Nội dung không hợp lệ."),
    "unknown_revision": (422, "Revision không tồn tại."),
    "lab_db_not_a_copy": (503, "Attack Lab chỉ ghi vào bản sao lab của database."),
}
_UNAVAILABLE = (500, "Attack Lab gặp lỗi khi đọc hoặc ghi note.")


def lab_http_error(error: LabError) -> tuple[int, str]:
    return LAB_ERRORS.get(error.category, _UNAVAILABLE)


class LabRunGuard:
    """Keeps lab writes and business runs from overlapping.

    A write holds ``write()``: new runs wait until it ends, and ``active()`` (the lab's
    ``run_active``) is true while any run is in flight, so the lab refuses to write under it.
    """

    def __init__(self) -> None:
        self._condition = asyncio.Condition()
        self._active = 0
        self._writing = False

    def active(self) -> bool:
        return self._active > 0

    @asynccontextmanager
    async def run(self) -> AsyncIterator[None]:
        async with self._condition:
            await self._condition.wait_for(lambda: not self._writing)
            self._active += 1
        try:
            yield
        finally:
            async with self._condition:
                self._active -= 1
                self._condition.notify_all()

    @asynccontextmanager
    async def write(self) -> AsyncIterator[None]:
        async with self._condition:
            await self._condition.wait_for(lambda: not self._writing)
            self._writing = True
        try:
            yield
        finally:
            async with self._condition:
                self._writing = False
                self._condition.notify_all()


def lab_revisions(lab: AttackLab | None) -> dict[str, dict] | None:
    """``{target: {revision, content_hash}}`` for lab targets that have been written or read.

    ``None`` when the lab is off or its store is unreadable; a run must never fail because of it.
    """
    if lab is None:
        return None
    try:
        revisions = {}
        for target in lab.targets:
            history = lab.history(target)
            if history:
                revisions[target] = {
                    "revision": history[-1].revision,
                    "content_hash": history[-1].content_hash,
                }
        return revisions
    except LabError:
        return None
