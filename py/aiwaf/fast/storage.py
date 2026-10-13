"""FastAPI compatibility exports for shared AIWAF runtime storage."""

from aiwaf.core.runtime_storage import (
    BlacklistStore,
    CSVStorage,
    DBStorage,
    ExemptionStore,
    FileStorage,
    GeoBlockStore,
    KeywordStore,
    MemoryStorage,
    StorageBackend,
    get_blacklist_store,
    get_geo_block_store,
    get_exemption_store,
    get_keyword_store,
    get_storage,
    initialize_storage,
)
from aiwaf.core.policy_csv_storage import PolicyCSVStorage

__all__ = [
    "StorageBackend",
    "MemoryStorage",
    "FileStorage",
    "CSVStorage",
    "PolicyCSVStorage",
    "DBStorage",
    "ExemptionStore",
    "BlacklistStore",
    "KeywordStore",
    "GeoBlockStore",
    "initialize_storage",
    "get_storage",
    "get_exemption_store",
    "get_blacklist_store",
    "get_keyword_store",
    "get_geo_block_store",
]
