from __future__ import annotations

from dataclasses import dataclass, field
from typing import Protocol


class MemoryStore(Protocol):
    def append(self, run_id: str, kind: str, value: str) -> None: ...

    def get(self, run_id: str, kind: str | None = None) -> tuple[str, ...]: ...


@dataclass
class InMemoryMemory:
    _entries: dict[str, list[tuple[str, str]]] = field(default_factory=dict)

    def append(self, run_id: str, kind: str, value: str) -> None:
        self._entries.setdefault(run_id, []).append((kind, value))

    def get(self, run_id: str, kind: str | None = None) -> tuple[str, ...]:
        return tuple(
            value
            for entry_kind, value in self._entries.get(run_id, ())
            if kind is None or entry_kind == kind
        )
