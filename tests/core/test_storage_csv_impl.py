from aiwaf.core import storage_csv_impl


def test_allowlist_and_blocklist_mutations_round_trip(tmp_path):
    storage_csv_impl.ensure_all(tmp_path)
    storage_csv_impl.rewrite_allowlist(tmp_path, {"203.0.113.1"})
    assert storage_csv_impl.read_allowlist(tmp_path) == {"203.0.113.1"}
    storage_csv_impl.append_blocklist(
        tmp_path,
        "203.0.113.2",
        "test",
        '{"path":"/admin"}',
        {"reputation_reason": "legacy_blacklist", "permanent": True},
    )
    rows = storage_csv_impl.legacy_blocklist_entries(tmp_path)
    assert "203.0.113.2" in rows
