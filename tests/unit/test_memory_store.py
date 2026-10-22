import pytest

from sqlguard.memory.store import InMemoryMemory


def test_memory_expires_by_run_and_cleans_expired_entries():
    now = [10.0]
    memory = InMemoryMemory(ttl_seconds=5, clock=lambda: now[0])
    memory.append("run-1", "note", "first")
    memory.append("run-2", "note", "second")

    now[0] = 14.0
    assert memory.get("run-1") == ("first",)
    memory.append("run-1", "note", "refreshed")

    now[0] = 15.0
    assert memory.get("run-2") == ()
    assert memory.get("run-1") == ("first", "refreshed")

    now[0] = 19.0
    assert memory.cleanup_expired() == 1
    assert memory.get("run-1") == ()


def test_memory_isolated_by_run_id():
    memory = InMemoryMemory()
    memory.append("run-1", "note", "private to first run")
    memory.append("run-2", "note", "private to second run")

    assert memory.get("run-1") == ("private to first run",)
    assert memory.get("run-2") == ("private to second run",)


@pytest.mark.parametrize("ttl_seconds", [0, -1, float("inf"), float("nan")])
def test_memory_rejects_invalid_ttl(ttl_seconds):
    with pytest.raises(ValueError, match="TTL"):
        InMemoryMemory(ttl_seconds=ttl_seconds)
