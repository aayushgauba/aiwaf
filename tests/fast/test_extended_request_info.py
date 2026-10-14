from aiwaf.core.runtime_blocklist import BlocklistManager
from aiwaf.core.runtime_storage import initialize_storage


def test_block_info_contains_basic_fields():
    initialize_storage(backend="memory")
    BlocklistManager.block("203.0.113.77", "unit-test reason", duration=60)

    info = BlocklistManager.get_block_info("203.0.113.77")
    assert info is not None
    assert info["ip"] == "203.0.113.77"
    assert info["reason"] == "unit-test reason"
    assert info["reputation_reason"].startswith("unit-test reason;")
    assert info["score"] == 10
    assert info["offenses"] == 1
    assert info["expires_at"] > info["blocked_at"]
    assert info["permanent"] is False


def test_block_info_can_store_extended_request_info():
    initialize_storage(backend="memory")
    BlocklistManager.block(
        "203.0.113.78",
        "unit-test reason",
        duration=60,
        extended_request_info={"path": "/login", "method": "POST"},
    )
    info = BlocklistManager.get_block_info("203.0.113.78")
    assert info is not None
    assert info.get("extended_request_info") == {"path": "/login", "method": "POST"}
