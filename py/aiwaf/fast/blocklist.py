"""FastAPI compatibility exports for shared AIWAF runtime blocklist manager."""

from aiwaf.core.runtime_blocklist import BlocklistManager

__all__ = ["BlocklistManager"]


# Compatibility aliases for callers using the previous terminology.
BlacklistManager = BlocklistManager
