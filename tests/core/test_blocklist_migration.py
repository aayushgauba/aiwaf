from aiwaf.core.blocklist_migration import legacy_metadata, migrate_csv_directory
from aiwaf.core.storage_csv_impl import append_blocklist, ensure_all


def test_migrate_csv_directory_reports_total_and_legacy(tmp_path):
    ensure_all(tmp_path)
    append_blocklist(
        tmp_path,
        "203.0.113.3",
        "old",
        "",
        {"reputation_reason": "legacy_blacklist", "permanent": True},
    )
    assert migrate_csv_directory(tmp_path) == (1, 1)


def test_legacy_metadata_normalizes_reason_and_timestamp():
    metadata = legacy_metadata("  imported block  ", now=123.5)

    assert metadata == {
        "reason": "imported block",
        "reputation_reason": "legacy_blacklist",
        "reasons": ["legacy_blacklist", "imported block"],
        "score": 100,
        "offenses": 1,
        "blocked_at": 123.5,
        "expires_at": None,
        "duration": None,
        "permanent": True,
    }
    assert legacy_metadata("", now=1)["reason"] == "legacy block"
