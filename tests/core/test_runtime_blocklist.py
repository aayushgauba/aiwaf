"""Additional blocklist manager edge-case coverage."""

import time

from aiwaf.core.runtime_blocklist import BlocklistManager
from aiwaf.core.runtime_storage import get_exemption_store, get_storage


def test_cleanup_expired_removes_old_temporary_blocks_without_ttl():
    storage = get_storage()
    storage.set(
        "blocked:198.51.100.50",
        {
            "ip": "198.51.100.50",
            "reason": "manual old block",
            "blocked_at": time.time() - 120,
            "duration": 60,
            "permanent": False,
        },
    )

    cleaned = BlocklistManager.cleanup_expired()
    assert cleaned == 1
    assert not BlocklistManager.is_blocked("198.51.100.50")


def test_get_recent_blocks_returns_sorted_by_newest_first():
    BlocklistManager.block("203.0.113.1", "reason one", duration=300)
    time.sleep(0.01)
    BlocklistManager.block("203.0.113.2", "reason two", duration=300)

    recent = BlocklistManager.get_recent_blocks(hours=1)
    ips = [entry["ip"] for entry in recent if entry["ip"] in {"203.0.113.1", "203.0.113.2"}]
    assert ips[:2] == ["203.0.113.2", "203.0.113.1"]


def test_top_blocked_reasons_respects_limit_and_counts():
    BlocklistManager.block("198.51.100.1", "A", duration=60)
    BlocklistManager.block("198.51.100.2", "A", duration=60)
    BlocklistManager.block("198.51.100.3", "B", duration=60)

    top = BlocklistManager.get_top_blocked_reasons(limit=1)
    assert len(top) == 1
    assert top[0]["reason"] == "A"
    assert top[0]["count"] >= 2


def test_bulk_operations_handle_errors_and_continue(monkeypatch):
    original_block = BlocklistManager.block

    def fake_block(ip, reason, duration=None):
        if ip == "bad":
            raise RuntimeError("boom")
        return original_block(ip, reason, duration)

    monkeypatch.setattr(BlocklistManager, "block", fake_block)

    result = BlocklistManager.bulk_block(["ok", "bad"], "reason", duration=10)
    assert result["ok"] is True
    assert result["bad"] is False


def test_get_allowlist_returns_both_ips_and_patterns():
    BlocklistManager.add_to_allowlist("192.0.2.9", "trusted")

    get_exemption_store().add_pattern("198.18.*.*", "trusted range")
    allowlist = BlocklistManager.get_allowlist()

    assert "192.0.2.9" in allowlist["ips"]
    assert "198.18.*.*" in allowlist["patterns"]
