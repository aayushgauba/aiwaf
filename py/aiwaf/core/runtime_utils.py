"""
Core utility functions for AIWAF
"""
import ipaddress

from typing import Optional, Set, List
from fastapi import Request
import logging
from aiwaf.core.defaults import DEFAULT_EXEMPT_PATHS_FLASK
from aiwaf.core.exemptions import is_path_exempt as core_is_path_exempt
from aiwaf.core.utils import (
    ip_in_allowlist as core_ip_in_allowlist,
)
from aiwaf.core.request_context import resolve_ip_from_fastapi_request
from aiwaf.core.request_context import extract_blocklist_extended_info_from_fastapi_request

logger = logging.getLogger(__name__)


def get_ip(request: Request) -> str:
    """
    Extract the real IP address from the request, considering proxy headers.
    """
    return resolve_ip_from_fastapi_request(request)


def is_private_ip(ip: str) -> bool:
    """Check if IP address is in private range."""
    try:
        ip_obj = ipaddress.ip_address(ip)
        return ip_obj.is_private
    except ValueError:
        return False


def is_exempt(request: Request, exempt_paths: Optional[Set[str]] = None) -> bool:
    """
    Check if a request should be exempt from AIWAF processing.
    
    Args:
        request: FastAPI Request object
        exempt_paths: Set of paths to exempt from processing
        
    Returns:
        True if request should be exempted
    """
    if exempt_paths is None:
        exempt_paths = set(DEFAULT_EXEMPT_PATHS_FLASK) | {
            '/healthz',
            '/metrics',
        }
    
    path = request.url.path
    
    if core_is_path_exempt(path, exempt_paths, allow_wildcards=True, allow_prefix=True):
        return True

    # Fast-specific convenience API health prefixes.
    if path.startswith('/api/health') or path.startswith('/api/status'):
        return True

    return is_view_exempt(request)


def is_view_exempt(request: Request) -> bool:
    """Check if the resolved route endpoint is marked as AIWAF-exempt."""
    endpoint = request.scope.get("endpoint") if hasattr(request, "scope") else None
    if endpoint is None:
        return False

    if getattr(endpoint, "aiwaf_exempt", False) or getattr(endpoint, "_aiwaf_exempt", False):
        return True

    # Some integrations may attach a class-based handler.
    endpoint_class = getattr(endpoint, "__self__", None)
    if endpoint_class is not None:
        cls = endpoint_class.__class__
        if getattr(cls, "aiwaf_exempt", False) or getattr(cls, "_aiwaf_exempt", False):
            return True

    return False


def is_static_file(path: str) -> bool:
    """
    Check if the request is for a static file based on file extension.
    
    Args:
        path: Request path
        
    Returns:
        True if path appears to be a static file
    """
    static_extensions = {
        '.css', '.js', '.png', '.jpg', '.jpeg', '.gif', '.ico', '.svg',
        '.woff', '.woff2', '.ttf', '.eot', '.otf', '.map', '.json',
        '.xml', '.txt', '.pdf', '.zip', '.tar', '.gz', '.webp', '.avif'
    }
    
    path_lower = path.lower()
    
    # Check file extensions
    for ext in static_extensions:
        if path_lower.endswith(ext):
            return True
    
    return False


def sanitize_header_value(value: str, max_length: int = 500) -> str:
    """
    Sanitize header value for logging/storage.
    
    Args:
        value: Header value to sanitize
        max_length: Maximum allowed length
        
    Returns:
        Sanitized header value
    """
    if not value:
        return ""
    
    # Truncate if too long
    if len(value) > max_length:
        value = value[:max_length] + "..."
    
    # Remove any control characters but keep printable ones
    sanitized = ''.join(char for char in value if ord(char) >= 32 or char in '\t\n\r')
    
    return sanitized


def ip_in_allowlist(ip: str, allowlist) -> bool:
    """Compatibility wrapper around shared allowlist helper."""
    return core_ip_in_allowlist(ip, allowlist)


def get_blocklist_extended_info(request: Request):
    """
    Build optional extended-request-info payload for blocklist entries.
    """
    app = getattr(request, "app", None)
    state = getattr(app, "state", None)
    cfg = getattr(state, "aiwaf_config", None)
    if cfg is None:
        return None

    def _cfg(key: str, default):
        try:
            if hasattr(cfg, "get"):
                return cfg.get(key, default)
        except Exception:
            pass
        return default

    enabled = bool(
        _cfg("AIWAF_BLOCKLIST_STORE_EXTENDED_INFO", False)
        or _cfg("AIWAF_CAPTURE_EXTENDED_REQUEST_INFO", False)
    )
    return extract_blocklist_extended_info_from_fastapi_request(
        request,
        enabled=enabled,
        max_headers=int(_cfg("AIWAF_BLOCKLIST_MAX_HEADERS", 50)),
        max_value_len=int(_cfg("AIWAF_BLOCKLIST_MAX_HEADER_VALUE_LENGTH", 512)),
        redact_headers=_cfg("AIWAF_BLOCKLIST_REDACT_HEADERS", ["Authorization", "Cookie", "Set-Cookie"]),
    )


def parse_user_agent(user_agent: str) -> dict:
    """
    Parse user agent string to extract basic information.
    
    Args:
        user_agent: User agent string
        
    Returns:
        Dictionary with parsed information
    """
    if not user_agent:
        return {"browser": "unknown", "version": "unknown", "os": "unknown"}
    
    ua_lower = user_agent.lower()
    result = {"browser": "unknown", "version": "unknown", "os": "unknown"}
    
    # Detect browser
    if "chrome" in ua_lower and "edg" not in ua_lower:
        result["browser"] = "chrome"
    elif "firefox" in ua_lower:
        result["browser"] = "firefox"
    elif "safari" in ua_lower and "chrome" not in ua_lower:
        result["browser"] = "safari"
    elif "edg" in ua_lower:
        result["browser"] = "edge"
    elif "opera" in ua_lower or "opr" in ua_lower:
        result["browser"] = "opera"
    
    # Detect OS
    if "windows" in ua_lower:
        result["os"] = "windows"
    elif "mac" in ua_lower or "darwin" in ua_lower:
        result["os"] = "macos"
    elif "linux" in ua_lower:
        result["os"] = "linux"
    elif "android" in ua_lower:
        result["os"] = "android"
    elif "iphone" in ua_lower or "ipad" in ua_lower:
        result["os"] = "ios"
    
    return result


def get_request_fingerprint(request: Request) -> str:
    """
    Generate a fingerprint for the request based on headers and other characteristics.
    
    Args:
        request: FastAPI Request object
        
    Returns:
        Fingerprint string
    """
    import hashlib
    
    # Collect fingerprinting data
    fingerprint_data = []
    
    # Add key headers
    key_headers = [
        'user-agent',
        'accept',
        'accept-language', 
        'accept-encoding',
        'connection'
    ]
    
    for header in key_headers:
        value = request.headers.get(header, '')
        fingerprint_data.append(f"{header}:{value}")
    
    # Add request method and path pattern
    fingerprint_data.append(f"method:{request.method}")
    
    # Create hash
    fingerprint_string = "|".join(fingerprint_data)
    return hashlib.md5(fingerprint_string.encode()).hexdigest()[:16]


class RateLimiter:
    """Simple in-memory rate limiter."""
    
    def __init__(self):
        self._requests = {}  # {ip: [(timestamp, path), ...]}
        self._cleanup_interval = 300  # 5 minutes
        self._last_cleanup = 0
    
    def is_rate_limited(self, ip: str, path: str, max_requests: int = 100, 
                       window_seconds: int = 300) -> bool:
        """
        Check if IP is rate limited.
        
        Args:
            ip: IP address
            path: Request path
            max_requests: Maximum requests allowed in window
            window_seconds: Time window in seconds
            
        Returns:
            True if rate limited
        """
        import time
        
        current_time = time.time()
        
        # Cleanup old entries periodically
        if current_time - self._last_cleanup > self._cleanup_interval:
            self._cleanup_old_entries(current_time, window_seconds * 2)
            self._last_cleanup = current_time
        
        # Get or create request list for this IP
        if ip not in self._requests:
            self._requests[ip] = []
        
        requests = self._requests[ip]
        
        # Remove old requests outside the window
        cutoff_time = current_time - window_seconds
        requests[:] = [(ts, p) for ts, p in requests if ts > cutoff_time]
        
        # Check if over limit
        if len(requests) >= max_requests:
            return True
        
        # Add current request
        requests.append((current_time, path))
        
        return False
    
    def _cleanup_old_entries(self, current_time: float, max_age: int):
        """Clean up old entries to prevent memory leak."""
        cutoff_time = current_time - max_age
        
        for ip in list(self._requests.keys()):
            requests = self._requests[ip]
            requests[:] = [(ts, p) for ts, p in requests if ts > cutoff_time]
            
            # Remove empty lists
            if not requests:
                del self._requests[ip]


# Compatibility aliases for callers using the previous terminology.
extract_blacklist_extended_info_from_fastapi_request = extract_blocklist_extended_info_from_fastapi_request
get_blacklist_extended_info = get_blocklist_extended_info
