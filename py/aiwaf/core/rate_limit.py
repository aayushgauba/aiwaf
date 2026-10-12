"""Shared rate-limiting helpers for framework adapters."""

from dataclasses import dataclass
from typing import Iterable, List
import threading
from .native_runtime import function as native_function

_bucket_lock = threading.RLock()


ALLOW = "allow"
THROTTLE = "throttle"
FLOOD_BLOCK = "flood_block"


@dataclass(frozen=True)
class RateLimitDecision:
    action: str
    count: int
    timestamps: List[float]


class RateCacheUnavailable(RuntimeError):
    """A backend failure must not turn a shared rate limit into an allow."""


def normalize_rate_key_mode(mode: str) -> str:
    """Normalize configured key mode to a supported value."""
    mode_value = (mode or "").strip().lower()
    if mode_value in {"ip", "ip_only"}:
        return "ip"
    return "ip_path"


def build_rate_limit_key(prefix: str, ip: str, path: str, key_mode: str = "ip_path", app_key: str = "") -> str:
    """Build a consistent cache key for rate limiting."""
    mode = normalize_rate_key_mode(key_mode)
    ip_value = ip or "unknown"
    path_value = path or "unknown"
    app_part = f"{app_key}:" if app_key else ""
    if mode == "ip":
        return f"{prefix}:{app_part}{ip_value}"
    return f"{prefix}:{app_part}{ip_value}:{path_value}"


def evaluate_rate_limit(
    timestamps: Iterable[float],
    now: float,
    window_seconds: float,
    max_requests: int,
    flood_threshold: int,
) -> RateLimitDecision:
    """
    Evaluate request rate and return action + updated timestamp window.

    Actions:
    - allow: request is allowed
    - throttle: request exceeds soft limit (429)
    - flood_block: request exceeds hard limit (403 + blacklist)
    """
    window = max(float(window_seconds), 1.0)
    native = native_function('policy_rate')
    if native is not None:
        action, count, updated = native(list(timestamps or []), float(now), window,
                                        int(max_requests), int(flood_threshold))
        return RateLimitDecision(action, count, updated)
    trimmed = [t for t in list(timestamps or []) if now - t < window]
    trimmed.append(now)
    count = len(trimmed)

    action = ALLOW
    if count > int(flood_threshold):
        action = FLOOD_BLOCK
    elif count > int(max_requests):
        action = THROTTLE

    return RateLimitDecision(action=action, count=count, timestamps=trimmed)


def consume_rate_limit(cache, key, *, now, window_seconds, max_requests, flood_threshold):
    try:
        return _consume_rate_limit(cache, key, now=now, window_seconds=window_seconds,
                                   max_requests=max_requests, flood_threshold=flood_threshold)
    except RateCacheUnavailable:
        raise
    except Exception:
        raise RateCacheUnavailable('Rate cache unavailable') from None


def _consume_rate_limit(cache, key, *, now, window_seconds, max_requests, flood_threshold):
    """Update a bucket atomically, including across workers for Redis backends."""
    atomic = getattr(cache, "consume_rate_limit", None)
    if callable(atomic):
        return atomic(key, now=now, window_seconds=window_seconds,
                      max_requests=max_requests, flood_threshold=flood_threshold)
    # Legacy dict/custom local caches still need one lock around read/modify/write.
    with _bucket_lock:
        decision = evaluate_rate_limit(cache.get(key) or [], now, window_seconds,
                                       max_requests, flood_threshold)
        cache.set(key, decision.timestamps, ttl_seconds=max(float(window_seconds), 1.0))
        return decision
