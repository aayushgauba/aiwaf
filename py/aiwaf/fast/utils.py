"""FastAPI compatibility exports for shared AIWAF runtime utilities."""

from aiwaf.core.runtime_utils import (
    RateLimiter,
    get_blocklist_extended_info,
    get_ip,
    get_request_fingerprint,
    ip_in_allowlist,
    is_exempt,
    is_private_ip,
    is_static_file,
    is_view_exempt,
    parse_user_agent,
    sanitize_header_value,
)

__all__ = [
    "get_ip",
    "get_blocklist_extended_info",
    "is_private_ip",
    "is_exempt",
    "is_view_exempt",
    "is_static_file",
    "sanitize_header_value",
    "ip_in_allowlist",
    "parse_user_agent",
    "get_request_fingerprint",
    "RateLimiter",
]


# Compatibility aliases for callers using the previous terminology.
get_blacklist_extended_info = get_blocklist_extended_info
