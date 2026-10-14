"""Helpers for upgrading existing blocklist records."""

from __future__ import annotations

import time
from pathlib import Path
from typing import Any

from . import storage_csv_impl


def legacy_metadata(reason: Any, *, now: float | None = None) -> dict[str, Any]:
    """Return current-schema metadata for a pre-reputation block."""
    timestamp = time.time() if now is None else float(now)
    detail = str(reason or "legacy block").strip() or "legacy block"
    return {
        "reason": detail,
        "reputation_reason": "legacy_blacklist",
        "reasons": ["legacy_blacklist", detail],
        "score": 100,
        "offenses": 1,
        "blocked_at": timestamp,
        "expires_at": None,
        "duration": None,
        "permanent": True,
    }


def migrate_csv_directory(data_dir: str | Path) -> tuple[int, int]:
    """Upgrade blacklist.csv and return (total entries, legacy entries)."""
    directory = Path(data_dir)
    blocklist = storage_csv_impl.read_blocklist(directory)
    legacy = storage_csv_impl.legacy_blocklist_entries(directory)
    return len(blocklist), len(legacy)


def migrate_runtime_storage(storage) -> tuple[int, int]:
    """Backfill legacy ``blocked:*`` values in a shared runtime backend."""
    keys = list(storage.get_all_keys("blocked:*"))
    changed = 0
    now = time.time()
    for key in keys:
        value = storage.get(key)
        if isinstance(value, dict) and value.get("reputation_reason"):
            continue
        if isinstance(value, dict):
            migrated = dict(value)
            migrated.update(legacy_metadata(value.get("reason"), now=now))
            extended = value.get("extended_request_info")
            if extended is not None:
                migrated["extended_request_info"] = extended
        else:
            migrated = legacy_metadata(value, now=now)
        storage.set(key, migrated)
        changed += 1
    return len(keys), changed
