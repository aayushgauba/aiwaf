"""Synchronous cache I/O for Rust honeypot timing; no Python policy decisions."""
import hashlib
import inspect
import json
import math

from .cache_backend import _redis_from_url


def synchronous(value):
    if inspect.isawaitable(value):
        if inspect.iscoroutine(value):
            value.close()
        raise TypeError("Honeypot cache methods must be synchronous")
    return value


class RedisHoneypotCache:
    """Strict JSON values and explicit Redis expiry; transport errors propagate."""
    def __init__(self, url):
        if not isinstance(url, str) or not url:
            raise ValueError("honeypot_redis_url is required for the Redis honeypot backend")
        self.client = _redis_from_url(url, timeout=2.0)

    def get(self, key):
        raw = synchronous(self.client.get(key))
        return None if raw is None else json.loads(raw)

    def set(self, key, value, *, timeout):
        result = synchronous(self.client.setex(key, int(timeout), json.dumps(value, allow_nan=False)))
        if result is False:
            raise RuntimeError("Honeypot Redis write failed")


class HoneypotCache:
    """Adapt get(key), set(key, value, timeout=seconds), e.g. Flask-Caching."""
    def __init__(self, backend, *, namespace="aiwaf:native:honeypot:v1"):
        for name in ("get", "set"):
            method = getattr(backend, name, None)
            if not callable(method) or inspect.iscoroutinefunction(method):
                raise TypeError("Honeypot cache requires synchronous get and set methods")
        if not isinstance(namespace, str) or not namespace or len(namespace.encode("utf-8")) > 100:
            raise ValueError("honeypot_cache_namespace must be a nonempty string of at most 100 bytes")
        self.backend = backend
        self.namespace = namespace

    def key(self, ip):
        return self.namespace + ":" + hashlib.sha256(ip.encode("utf-8")).hexdigest()

    def get_timestamp(self, ip):
        value = synchronous(self.backend.get(self.key(ip)))
        if value is None:
            return None
        if (not isinstance(value, (tuple, list)) or len(value) != 2 or
                any(isinstance(item, bool) or not isinstance(item, (int, float)) or not math.isfinite(item) for item in value)):
            raise ValueError("Invalid cached honeypot timestamp")
        return tuple(value)

    def set_timestamp(self, ip, timestamp, expires_at, ttl_seconds):
        result = synchronous(self.backend.set(self.key(ip), (timestamp, expires_at), timeout=ttl_seconds))
        if result is False:
            raise RuntimeError("Honeypot cache write failed")
