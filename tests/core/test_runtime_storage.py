"""
Storage and blacklist tests for AIWAF.
"""
import time

from aiwaf.core.runtime_blacklist import BlacklistManager
from aiwaf.core.runtime_storage import FileStorage, get_blacklist_store, get_exemption_store, get_storage


def test_memory_storage_ttl_expiration():
    backend = get_storage()
    backend.set("temp", "value", ttl=1)
    assert backend.get("temp") == "value"
    time.sleep(1.1)
    assert backend.get("temp") is None


def test_file_storage_persistence(tmp_path):
    file_path = tmp_path / "aiwaf_store.json"
    backend = FileStorage(str(file_path))
    backend.set("persist", {"ok": True})

    reloaded = FileStorage(str(file_path))
    assert reloaded.get("persist") == {"ok": True}


def test_exemption_store_manages_ips_and_patterns():
    store = get_exemption_store()
    store.add_ip("203.0.113.4", "testing exemption")
    assert store.is_exempted("203.0.113.4")

    store.add_pattern("198.51.100.*", "CIDR range")
    assert store.is_exempted("198.51.100.5")

    assert store.remove_ip("203.0.113.4")
    assert not store.is_exempted("203.0.113.4")

    assert store.remove_pattern("198.51.100.*")


def test_blacklist_store_block_unblock_flow():
    store = get_blacklist_store()
    store.block_ip("198.51.100.10", "test block", duration=60)

    assert store.is_blocked("198.51.100.10")
    info = store.get_block_info("198.51.100.10")
    assert info is not None and info["reason"] == "test block"

    blocked_ips = store.get_blocked_ips()
    assert "198.51.100.10" in blocked_ips

    stats = store.get_block_stats()
    assert stats["total_blocked"] == 1
    assert stats["reason_counts"].get("test block") == 1

    assert store.unblock_ip("198.51.100.10")
    assert not store.is_blocked("198.51.100.10")


def test_blacklist_manager_bulk_operations_and_recent_activity():
    block_ips = ["203.0.113.1", "203.0.113.2"]
    result = BlacklistManager.bulk_block(block_ips, "bulk test", duration=60)
    assert all(result.values())

    assert BlacklistManager.is_blocked("203.0.113.1")
    assert "203.0.113.2" in BlacklistManager.get_blocked_ips()

    recent = BlacklistManager.get_recent_blocks(hours=1)
    assert any(entry["ip"] == "203.0.113.1" for entry in recent)

    top_reasons = BlacklistManager.get_top_blocked_reasons(limit=2)
    assert top_reasons and top_reasons[0]["reason"].startswith("bulk test")

    unblock_result = BlacklistManager.bulk_unblock(["203.0.113.1"])
    assert unblock_result["203.0.113.1"]


def test_blacklist_manager_temporary_and_permanent_blocks():
    assert BlacklistManager.block_temporary("198.51.100.20", "temp reason", minutes=1)
    assert BlacklistManager.block_permanent("198.51.100.21", "perm reason")

    assert BlacklistManager.is_blocked("198.51.100.20")
    assert BlacklistManager.is_blocked("198.51.100.21")

    BlacklistManager.bulk_unblock(["198.51.100.20", "198.51.100.21"])
import time

from aiwaf.core import runtime_storage as storage_module
from aiwaf.core.runtime_storage import (
    CSVStorage,
    DBStorage,
    FileStorage,
    GeoBlockStore,
    KeywordStore,
    MemoryStorage,
    StorageBackend,
)


def test_abstract_storage_contract_methods_are_explicit():
    assert StorageBackend.get(None, "x") is None
    assert StorageBackend.set(None, "x", 1) is None
    assert StorageBackend.delete(None, "x") is None
    assert StorageBackend.exists(None, "x") is None
    assert StorageBackend.get_all_keys(None) is None


def test_file_storage_delete_exists_and_keys(tmp_path):
    backend = FileStorage(str(tmp_path / "values.json"))
    backend.set("user:1", {"name": "a"})
    backend.set("expired", 1, ttl=1)
    backend._data["expired"]["expires_at"] = time.time() - 1
    assert backend.exists("user:1")
    assert backend.get_all_keys("user:*") == ["user:1"]
    assert "expired" not in backend.get_all_keys()
    assert backend.delete("user:1") is True
    assert backend.delete("missing") is False


def test_csv_storage_real_round_trip_expiration_and_patterns(tmp_path):
    path = tmp_path / "values.csv"
    backend = CSVStorage(str(path))
    assert backend.set("user:1", {"name": "a"})
    assert backend.set("other", [1, 2])
    assert CSVStorage(str(path)).get("user:1") == {"name": "a"}
    assert backend.exists("other")
    assert backend.get_all_keys("user:*") == ["user:1"]
    backend.set("other", [1, 2], ttl=-1)
    assert backend.get("other") is None
    assert backend.delete("user:1") is True
    assert backend.delete("missing") is False


def test_db_storage_real_round_trip_expiration_and_patterns(tmp_path):
    backend = DBStorage(str(tmp_path / "values.db"))
    assert backend.set("user:1", {"name": "a"})
    assert backend.set("other", [1, 2])
    assert backend.get("user:1") == {"name": "a"}
    assert backend.exists("other")
    assert backend.get_all_keys("user:*") == ["user:1"]
    backend._conn.execute("UPDATE kv_store SET expires_at = ? WHERE key = ?", (time.time() - 1, "other"))
    backend._conn.commit()
    assert backend.get("other") is None
    assert backend.delete("user:1") is True
    assert backend.delete("missing") is False


def test_keyword_and_geo_stores_cover_mutations():
    backend = MemoryStorage()
    keywords = KeywordStore(backend)
    keywords.add_keyword("Admin", 2)
    keywords.add_keyword("login", 1)
    assert keywords.get_all_keywords() == ["admin", "login"]
    keywords.remove_keyword("admin")
    assert keywords.get_all_keywords() == ["login"]

    geo = GeoBlockStore(backend)
    geo.add_country("us")
    geo.add_country("")
    assert geo.get_countries() == {"US"}
    geo.remove_country("us")
    geo.remove_country("")
    assert geo.get_countries() == set()
