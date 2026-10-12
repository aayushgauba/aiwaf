from flask import request, g, has_request_context
from .storage import is_ip_whitelisted, get_path_exemptions
from aiwaf.core.defaults import DEFAULT_EXEMPT_PATHS_FLASK
from aiwaf.core.exemptions import is_path_exempt as core_is_path_exempt
from aiwaf.core.exemptions import native_path_rules, normalize_path
from aiwaf.core.native_runtime import csv_function
from aiwaf.core.request_context import (
    extract_blacklist_extended_info_from_flask_request,
    extract_ip_from_flask_request,
)


def _csv_exemption_signature(data_dir, ip, path):
    """Validate each reuse against external writes/replacements, even mid-request."""
    from flask import current_app
    from aiwaf.core.storage_schema import WHITELIST_CSV, PATH_EXEMPTIONS_CSV
    stamps = []
    for filename in (WHITELIST_CSV, PATH_EXEMPTIONS_CSV):
        try:
            meta = (data_dir / filename).stat()
        except FileNotFoundError:
            return None
        stamps.append((meta.st_dev, meta.st_ino, meta.st_size, meta.st_mtime_ns, meta.st_ctime_ns))
    configured = current_app.config.get('AIWAF_EXEMPT_PATHS', get_default_exempt_paths())
    return (str(data_dir), ip, path, tuple(sorted(str(p) for p in configured)), tuple(stamps))

def get_ip():
    return extract_ip_from_flask_request(request)

def is_exempt(request):
    """Check if request should be exempt from AIWAF protection."""
    ip = get_ip()
    from .storage import _get_storage_mode, _get_data_dir
    native = csv_function('csv_request_exempt') if _get_storage_mode() == 'csv' else None
    if native is not None:
        from pathlib import Path
        from aiwaf.core.storage_ops import ensure_csv_files
        from aiwaf.core.storage_schema import CSV_HEADERS, WHITELIST_CSV
        from flask import current_app
        data_dir = Path(_get_data_dir())
        path = normalize_path(request.path) if request.path else ''
        reuse = has_request_context() and current_app.config.get('AIWAF_CSV_REQUEST_CACHE', True)
        signature = _csv_exemption_signature(data_dir, ip, path) if reuse else None
        cached = getattr(g, '_aiwaf_csv_exemption', None) if reuse else None
        if signature is not None and cached is not None and cached[0] == signature:
            result = cached[1]
        else:
            ensure_csv_files(data_dir, CSV_HEADERS)
            before = _csv_exemption_signature(data_dir, ip, path) if reuse else None
            result = native(str(data_dir / WHITELIST_CSV), ip, path,
                            native_path_rules(get_exempt_paths()))
            after = _csv_exemption_signature(data_dir, ip, path) if reuse else None
            if reuse and before is not None and before == after:
                g._aiwaf_csv_exemption = (after, result)
        if result:
            return True
    else:
        result = None
    if result is None:
        if is_ip_whitelisted(ip) or is_path_exempt(request.path):
            return True
    
    # Decorator-based exemption
    if hasattr(request, 'endpoint') and request.endpoint:
        try:
            from flask import current_app
            endpoint_func = current_app.view_functions.get(request.endpoint)
            if endpoint_func and getattr(endpoint_func, '_aiwaf_exempt', False):
                return True
        except:
            pass
    
    return False

def is_path_exempt(path):
    """Check if a path should be exempt from AIWAF protection."""
    try:
        from flask import current_app
        exempt_paths = get_exempt_paths()
    except Exception:
        exempt_paths = get_default_exempt_paths()

    return core_is_path_exempt(path, exempt_paths, allow_wildcards=True, allow_prefix=True)


def get_exempt_paths():
    """Get configured path exemptions combined with stored exemptions."""
    try:
        from flask import current_app
        configured = current_app.config.get('AIWAF_EXEMPT_PATHS', get_default_exempt_paths())
    except Exception:
        configured = get_default_exempt_paths()
    stored = get_path_exemptions()
    combined = set()
    for path in configured:
        combined.add(str(path).lower())
    for path in stored:
        combined.add(str(path).lower())
    return combined

def get_default_exempt_paths():
    """Get default list of paths that should be exempt from AIWAF protection."""
    return set(DEFAULT_EXEMPT_PATHS_FLASK)


def get_blacklist_extended_info(request):
    """Build optional extended-request-info payload for blacklist entries."""
    try:
        from flask import current_app
        enabled = bool(
            current_app.config.get("AIWAF_BLACKLIST_STORE_EXTENDED_INFO", False)
            or current_app.config.get("AIWAF_CAPTURE_EXTENDED_REQUEST_INFO", False)
        )
        return extract_blacklist_extended_info_from_flask_request(
            request,
            enabled=enabled,
            max_headers=int(current_app.config.get("AIWAF_BLACKLIST_MAX_HEADERS", 50)),
            max_value_len=int(current_app.config.get("AIWAF_BLACKLIST_MAX_HEADER_VALUE_LENGTH", 512)),
            redact_headers=current_app.config.get(
                "AIWAF_BLACKLIST_REDACT_HEADERS",
                ["Authorization", "Cookie", "Set-Cookie"],
            ),
        )
    except Exception:
        return None
