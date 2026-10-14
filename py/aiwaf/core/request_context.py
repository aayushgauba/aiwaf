"""Shared request-context extraction across Django/Flask/FastAPI."""

from __future__ import annotations

import ipaddress
import json
from typing import Dict, Iterable, Optional

from .utils import get_ip_from_headers, get_ip_from_meta


def extract_ip_from_django_request(request) -> str:
    return get_ip_from_meta(getattr(request, "META", {}) or {})


def extract_ip_from_flask_request(request) -> str:
    headers = getattr(request, "headers", {}) or {}
    remote_addr = getattr(request, "remote_addr", None)
    return get_ip_from_headers(headers, remote_addr)


def extract_ip_from_fastapi_request(request) -> str:
    client = getattr(request, "client", None)
    client_ip = getattr(client, "host", None) if client else None
    # Keep existing Fast behavior baseline: prefer direct client unless missing.
    if client_ip:
        return client_ip
    return get_ip_from_headers(dict(getattr(request, "headers", {}) or {}), None)


def resolve_ip_from_fastapi_request(request) -> str:
    """
    Resolve the effective client IP for FastAPI requests using proxy-aware rules.
    """
    extracted = extract_ip_from_fastapi_request(request)
    if extracted and extracted != "unknown":
        client_ip = extracted
    else:
        client = getattr(request, "client", None)
        client_ip = getattr(client, "host", None) if client else None

    # Prefer direct public client IP.
    if client_ip and _is_valid_ip(client_ip) and not _is_proxy_like_ip(client_ip):
        return client_ip

    request_headers = dict(getattr(request, "headers", {}) or {})
    headers_lower = {str(k).lower(): v for k, v in request_headers.items()}

    # If request appears proxied/internal, trust first XFF hop if valid.
    if client_ip is None or _is_proxy_like_ip(client_ip):
        xff = headers_lower.get("x-forwarded-for")
        if xff:
            candidate = xff.split(",")[0].strip()
            if _is_valid_ip(candidate):
                return candidate

        extracted_from_headers = get_ip_from_headers(request_headers, client_ip)
        if extracted_from_headers and _is_valid_ip(extracted_from_headers):
            return extracted_from_headers

        for header in (
            "x-forwarded-for",
            "x-real-ip",
            "x-client-ip",
            "cf-connecting-ip",
            "x-forwarded",
            "forwarded-for",
            "forwarded",
        ):
            if header in headers_lower:
                ip = headers_lower[header].split(",", 1)[0].strip()
                if _is_valid_ip(ip):
                    return ip

    if client_ip:
        return client_ip
    return "unknown"


def extract_headers_from_django_request(request) -> Dict[str, str]:
    meta = getattr(request, "META", {}) or {}
    headers: Dict[str, str] = {}
    for key, value in meta.items():
        if key.startswith("HTTP_"):
            hdr = key[5:].replace("_", "-").lower()
            headers[hdr] = str(value)
        elif key in {"CONTENT_TYPE", "CONTENT_LENGTH"}:
            headers[key.replace("_", "-").lower()] = str(value)
    return headers


def extract_headers_from_flask_request(request) -> Dict[str, str]:
    return {str(k).lower(): str(v) for k, v in (getattr(request, "headers", {}) or {}).items()}


def extract_headers_from_fastapi_request(request) -> Dict[str, str]:
    return {str(k).lower(): str(v) for k, v in (getattr(request, "headers", {}) or {}).items()}


def extract_query_keys_from_django_request(request) -> Iterable[str]:
    return list((getattr(request, "GET", {}) or {}).keys())


def extract_query_keys_from_flask_request(request) -> Iterable[str]:
    return list((getattr(request, "args", {}) or {}).keys())


def extract_query_keys_from_fastapi_request(request) -> Iterable[str]:
    query = getattr(getattr(request, "url", None), "query", "") or ""
    if not query:
        return []
    keys = []
    for part in query.split("&"):
        if not part:
            continue
        keys.append(part.split("=", 1)[0])
    return keys


def normalized_headers_to_wsgi_environ(headers: Dict[str, str], http_version: str = "") -> Dict[str, str]:
    """
    Convert normalized lower-case HTTP headers into core environ format.
    """
    environ: Dict[str, str] = {}
    for key, value in (headers or {}).items():
        env_key = f"HTTP_{str(key).upper().replace('-', '_')}"
        environ[env_key] = str(value)
    if http_version:
        environ["SERVER_PROTOCOL"] = f"HTTP/{http_version}"
    return environ


def extract_logging_context_from_django_request(request, ip: str = "") -> Dict[str, str]:
    query = str(getattr(getattr(request, "META", {}), "get", lambda *_: "")("QUERY_STRING", "") or "")
    path = str(getattr(request, "path", "") or "")
    return {
        "ip": ip or extract_ip_from_django_request(request),
        "method": str(getattr(request, "method", "") or ""),
        "path": path,
        "query_string": query,
        "path_with_query": f"{path}?{query}" if query else path,
        "protocol": str(getattr(getattr(request, "META", {}), "get", lambda *_: "HTTP/1.1")("SERVER_PROTOCOL", "HTTP/1.1") or "HTTP/1.1"),
        "referer": str(getattr(getattr(request, "META", {}), "get", lambda *_: "")("HTTP_REFERER", "") or ""),
        "user_agent": str(getattr(getattr(request, "META", {}), "get", lambda *_: "")("HTTP_USER_AGENT", "") or ""),
    }


def extract_logging_context_from_flask_request(request, ip: str = "") -> Dict[str, str]:
    query_bytes = getattr(request, "query_string", b"") or b""
    query = query_bytes.decode("utf-8", errors="ignore") if isinstance(query_bytes, (bytes, bytearray)) else str(query_bytes)
    path = str(getattr(request, "path", "") or "")
    path_with_query = str(getattr(request, "full_path", "") or "")
    if not query:
        path_with_query = path
    return {
        "ip": ip or extract_ip_from_flask_request(request),
        "method": str(getattr(request, "method", "") or ""),
        "path": path,
        "query_string": query,
        "path_with_query": path_with_query,
        "protocol": str(getattr(getattr(request, "environ", {}), "get", lambda *_: "HTTP/1.1")("SERVER_PROTOCOL", "HTTP/1.1") or "HTTP/1.1"),
        "referer": str((getattr(request, "headers", {}) or {}).get("Referer", "") or ""),
        "user_agent": str((getattr(request, "headers", {}) or {}).get("User-Agent", "") or ""),
    }


def extract_logging_context_from_fastapi_request(request, ip: str = "") -> Dict[str, str]:
    query = str(getattr(getattr(request, "url", None), "query", "") or "")
    path = str(getattr(getattr(request, "url", None), "path", "") or "")
    headers = getattr(request, "headers", {}) or {}
    http_version = str((getattr(request, "scope", {}) or {}).get("http_version", "1.1") or "1.1")
    return {
        "ip": ip or resolve_ip_from_fastapi_request(request),
        "method": str(getattr(request, "method", "") or ""),
        "path": path,
        "query_string": query,
        "path_with_query": f"{path}?{query}" if query else path,
        "protocol": f"HTTP/{http_version}",
        "referer": str(headers.get("referer", "") or ""),
        "user_agent": str(headers.get("user-agent", "") or ""),
    }


def _normalize_capture_headers(
    headers: Dict[str, str],
    *,
    max_headers: int,
    max_value_len: int,
    redact_headers: Iterable[str],
    redact_token: str = "[redacted]",
    title_case_keys: bool = True,
) -> Dict[str, str]:
    redact = {str(h).strip().lower() for h in (redact_headers or []) if h}
    out: Dict[str, str] = {}
    for key, value in (headers or {}).items():
        if len(out) >= max_headers:
            break
        name = str(key)
        out_name = "-".join(part.capitalize() for part in name.split("-")) if title_case_keys else name
        val = str(value)
        if name.lower() in redact:
            out[out_name] = redact_token
            continue
        if max_value_len and len(val) > max_value_len:
            val = val[:max_value_len] + "...(truncated)"
        out[out_name] = val
    return out


def _enforce_payload_size_limit(payload: Dict[str, object], max_bytes: int, *, compact_fallback: Dict[str, object]) -> Dict[str, object]:
    compact = json.dumps(payload, separators=(",", ":"), ensure_ascii=False)
    if len(compact.encode("utf-8")) <= max_bytes:
        return payload

    payload = dict(payload)
    payload["headers"] = {}
    compact = json.dumps(payload, separators=(",", ":"), ensure_ascii=False)
    if len(compact.encode("utf-8")) <= max_bytes:
        return payload

    query_key = "query" if "query" in payload else "query_string"
    query_val = str(payload.get(query_key, "") or "")
    if query_val:
        payload[query_key] = query_val[:256]
        compact = json.dumps(payload, separators=(",", ":"), ensure_ascii=False)
        if len(compact.encode("utf-8")) <= max_bytes:
            return payload

    url_val = str(payload.get("url", "") or "")
    if url_val:
        payload["url"] = url_val[:256]
        compact = json.dumps(payload, separators=(",", ":"), ensure_ascii=False)
        if len(compact.encode("utf-8")) <= max_bytes:
            return payload

    return compact_fallback


def extract_blocklist_extended_info_from_django_request(
    request,
    *,
    enabled: bool,
    max_headers: int = 50,
    max_value_len: int = 512,
    redact_headers: Iterable[str] = ("Authorization", "Cookie", "Set-Cookie"),
) -> Optional[Dict[str, object]]:
    if not enabled:
        return None
    headers = _normalize_capture_headers(
        extract_headers_from_django_request(request),
        max_headers=max_headers,
        max_value_len=max_value_len,
        redact_headers=redact_headers,
        redact_token="[redacted]",
    )
    path = str(getattr(request, "path", "") or "")
    query = str(getattr(getattr(request, "META", {}), "get", lambda *_: "")("QUERY_STRING", "") or "")
    try:
        url = request.build_absolute_uri()
    except Exception:
        url = path
    info: Dict[str, object] = {"method": str(getattr(request, "method", "") or ""), "path": path, "url": url, "headers": headers}
    if query:
        info["query_string"] = query
    try:
        host = request.get_host()
        if host:
            info["host"] = host
    except Exception:
        pass
    return info


def extract_blocklist_extended_info_from_flask_request(
    request,
    *,
    enabled: bool,
    max_bytes: int = 4096,
    capture_headers: Iterable[str] = (),
    redact_headers: Iterable[str] = (),
) -> Optional[Dict[str, object]]:
    if not enabled:
        return None
    selected = {}
    all_headers = extract_headers_from_flask_request(request)
    for name in capture_headers:
        key = str(name).strip()
        if not key:
            continue
        lk = key.lower()
        if lk not in all_headers:
            continue
        selected[lk] = all_headers[lk]
    headers = _normalize_capture_headers(
        selected,
        max_headers=max(len(list(capture_headers)) or 50, 1),
        max_value_len=0,
        redact_headers=redact_headers,
        redact_token="[REDACTED]",
    )
    query_bytes = getattr(request, "query_string", b"") or b""
    query = query_bytes.decode("utf-8", errors="ignore") if isinstance(query_bytes, (bytes, bytearray)) else str(query_bytes)
    payload: Dict[str, object] = {
        "url": str(getattr(request, "url", "") or ""),
        "path": str(getattr(request, "path", "") or ""),
        "query": query,
        "method": str(getattr(request, "method", "") or ""),
        "host": str(getattr(request, "host", "") or ""),
        "headers": headers,
    }
    return _enforce_payload_size_limit(
        payload,
        max_bytes,
        compact_fallback={
            "path": payload["path"],
            "method": payload["method"],
            "host": payload["host"],
            "truncated": True,
        },
    )


def extract_blocklist_extended_info_from_fastapi_request(
    request,
    *,
    enabled: bool,
    max_headers: int = 50,
    max_value_len: int = 512,
    redact_headers: Iterable[str] = ("authorization", "cookie", "set-cookie"),
) -> Optional[Dict[str, object]]:
    if not enabled:
        return None
    ctx = extract_logging_context_from_fastapi_request(request)
    headers = _normalize_capture_headers(
        extract_headers_from_fastapi_request(request),
        max_headers=max_headers,
        max_value_len=max_value_len,
        redact_headers=redact_headers,
        redact_token="[redacted]",
    )
    info: Dict[str, object] = {
        "method": ctx["method"],
        "path": ctx["path"],
        "url": ctx["path_with_query"],
        "headers": headers,
    }
    if ctx["query_string"]:
        info["query_string"] = ctx["query_string"]
    host = str(getattr(getattr(request, "url", None), "netloc", "") or "")
    if host:
        info["host"] = host
    return info


def _is_valid_ip(ip: str) -> bool:
    try:
        ipaddress.ip_address(ip)
        return True
    except ValueError:
        return False


def _is_proxy_like_ip(ip: str) -> bool:
    try:
        ip_obj = ipaddress.ip_address(ip)
        return (
            ip_obj.is_private
            or ip_obj.is_loopback
            or ip_obj.is_link_local
            or ip_obj.is_reserved
        )
    except ValueError:
        return False


# Compatibility aliases for callers using the previous terminology.
extract_blacklist_extended_info_from_django_request = extract_blocklist_extended_info_from_django_request
extract_blacklist_extended_info_from_flask_request = extract_blocklist_extended_info_from_flask_request
extract_blacklist_extended_info_from_fastapi_request = extract_blocklist_extended_info_from_fastapi_request
