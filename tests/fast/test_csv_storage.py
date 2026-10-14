from aiwaf.fast.storage import get_blocklist_store, get_exemption_store, initialize_storage


def test_fast_storage_allowlist_and_blocklist_operations():
    initialize_storage(backend="memory")
    exemptions = get_exemption_store()
    blocklist = get_blocklist_store()

    exemptions.add_ip("192.0.2.10", "trusted")
    assert exemptions.is_exempted("192.0.2.10")

    blocklist.block_ip("198.51.100.20", "test")
    assert blocklist.is_blocked("198.51.100.20")
