"""
Shared exemption helpers for paths and path rules.
"""

from __future__ import annotations

import fnmatch
import re
import os
import ipaddress
from functools import lru_cache
from .native_runtime import function as native_function
from typing import Iterable, Mapping, Any, Optional


def normalize_path(path: str, trailing_slash: bool | None = None) -> str:
    if not path:
        return "/"
    cleaned = re.sub(r"/{2,}", "/", str(path).strip())
    if not cleaned.startswith("/"):
        cleaned = "/" + cleaned
    if trailing_slash is True and not cleaned.endswith("/"):
        cleaned += "/"
    if trailing_slash is False and cleaned != "/":
        cleaned = cleaned.rstrip("/")
    return cleaned.lower()


def normalize_paths(paths: Iterable[str]) -> list[str]:
    normalized: list[str] = []
    for path in paths:
        if not path:
            continue
        normalized.append(normalize_path(path))
    return normalized


def is_path_exempt(path: str, exempt_paths: Iterable[str], allow_wildcards: bool, allow_prefix: bool) -> bool:
    if not path:
        return False
    path_lower = normalize_path(path, trailing_slash=None)
    exempt_paths = tuple(exempt_paths)
    native = native_function('policy_path_exempt')
    if native is not None:
        rules = native_path_rules(exempt_paths, allow_wildcards)
        result = native(path_lower, rules, bool(allow_prefix))
        if result is not None:
            return result
    for exempt in exempt_paths:
        if not exempt:
            continue
        exempt_norm = normalize_path(exempt, trailing_slash=None)
        if allow_wildcards and "*" in exempt_norm:
            if fnmatch.fnmatch(path_lower, exempt_norm):
                return True
            continue
        if path_lower == exempt_norm:
            return True
        if allow_prefix:
            prefix = exempt_norm.rstrip("/")
            if prefix:
                if path_lower == prefix or path_lower.startswith(prefix + "/"):
                    return True
    return False


def native_path_rules(exempt_paths, allow_wildcards=True):
    rules = []
    for exempt in exempt_paths:
        if not exempt:
            continue
        exact = normalize_path(exempt)
        rules.append((exact, _native_glob(exact) if allow_wildcards and '*' in exact else None))
    return rules


@lru_cache(maxsize=256)
def _native_glob(pattern):
    # Compile Python's fnmatch grammar once per configuration pattern. Rust's
    # regex engine needs its end anchor and cannot use Python's atomic groups.
    # Removing atomicity preserves the accepted glob language.
    # Python fnmatch uses re.match, so its translation only adds an end anchor.
    # Rust is_match searches anywhere unless we add the start anchor explicitly.
    return r'\A' + fnmatch.translate(os.path.normcase(pattern)).replace('(?>', '(?:').replace('\\Z', '\\z')


@lru_cache(maxsize=256)
def _native_network(pattern):
    try:
        network = ipaddress.ip_network(pattern, strict=False)
        return str(network.network_address), network.prefixlen
    except ValueError:
        return None


def is_ip_exempt(ip, ips, patterns):
    """Match exact IPs, fnmatch patterns and IPv4/IPv6 networks."""
    patterns = tuple(patterns)
    native = native_function('policy_ip_exempt')
    if native is not None:
        networks = [network for pattern in patterns if '/' in pattern
                    if (network := _native_network(pattern)) is not None]
        result = native(ip, set(ips),
                        [_native_glob(pattern) for pattern in patterns], networks)
        if result is not None:
            return result
    if ip in ips:
        return True
    for pattern in patterns:
        if fnmatch.fnmatch(ip, pattern):
            return True
        if '/' in pattern:
            try:
                if ipaddress.ip_address(ip) in ipaddress.ip_network(pattern, strict=False):
                    return True
            except ValueError:
                continue
    return False


def get_path_rule_for_path(path: str, rules: Iterable[dict]) -> dict | None:
    if not path:
        return None
    normalized_path = normalize_path(path, trailing_slash=False)
    native = native_function('policy_path_rule_index')
    if native is not None:
        candidates = [(normalize_path(rule['PREFIX'], trailing_slash=True), rule)
                      for rule in rules if isinstance(rule, dict) and rule.get('PREFIX')]
        index = native(normalized_path, [prefix for prefix, _ in candidates])
        return candidates[index][1] if index is not None else None
    best = None
    for rule in rules:
        if not isinstance(rule, dict):
            continue
        prefix = normalize_path(rule.get("PREFIX"), trailing_slash=True) if rule.get("PREFIX") else None
        if not prefix:
            continue
        if normalized_path == prefix.rstrip("/") or normalized_path.startswith(prefix):
            if best is None or len(prefix) > len(best[0]):
                best = (prefix, rule)
    return best[1] if best else None


def normalize_middleware_name(name) -> str:
    if not name:
        return ""
    if not isinstance(name, str):
        name = getattr(name, "__name__", str(name))
    name = name.strip()
    mapping = {
        "ipandkeywordblockmiddleware": "ip_keyword_block",
        "ratelimitmiddleware": "rate_limit",
        "honeypottimingmiddleware": "honeypot",
        "headervalidationmiddleware": "header_validation",
        "geoblockmiddleware": "geo_block",
        "aianomalymiddleware": "ai_anomaly",
        "uuidtampermiddleware": "uuid_tamper",
        "aiwafloggingmiddleware": "logging",
    }
    if "." in name:
        name = name.split(".")[-1]
    normalized = name.lower()
    return mapping.get(normalized, normalized)


def get_path_rule_overrides_for_path(path: str, rules: Iterable[dict], section_key: str) -> dict:
    """Return override dict for section key from best-matching path rule."""
    if not path or not section_key:
        return {}
    rule = get_path_rule_for_path(path, rules)
    if not isinstance(rule, Mapping):
        return {}
    value = rule.get(section_key)
    if value is None:
        value = rule.get(str(section_key).lower())
    return value if isinstance(value, Mapping) else {}


def is_middleware_disabled_for_path(path: str, rules: Iterable[dict], middleware_name) -> bool:
    """Return whether PATH_RULES disables middleware for given path."""
    if not path:
        return False
    rule = get_path_rule_for_path(path, rules)
    if not isinstance(rule, Mapping):
        return False
    disabled: Any = rule.get("DISABLE")
    if disabled is None:
        disabled = rule.get("disable")
    if not isinstance(disabled, (list, tuple, set)):
        return False
    target = normalize_middleware_name(middleware_name)
    for entry in disabled:
        if normalize_middleware_name(entry) == target:
            return True
    return False


def should_apply_middleware_for_path(
    path: str,
    rules: Iterable[dict],
    middleware_name,
    *,
    fully_exempt: bool = False,
    exempt_middlewares: Optional[Iterable[str]] = None,
    required_middlewares: Optional[Iterable[str]] = None,
) -> bool:
    """
    Shared middleware gating policy.

    Precedence:
    1. Required middleware always applies.
    2. PATH_RULES disable denies execution.
    3. Full exemption denies execution.
    4. Per-middleware exemption denies execution.
    5. Otherwise middleware applies.
    """
    target = normalize_middleware_name(middleware_name)
    required = {
        normalize_middleware_name(item)
        for item in (required_middlewares or [])
        if item
    }
    if target in required:
        return True

    if is_middleware_disabled_for_path(path, rules, target):
        return False

    if fully_exempt:
        return False

    exempt = {
        normalize_middleware_name(item)
        for item in (exempt_middlewares or [])
        if item
    }
    if target in exempt:
        return False

    return True
