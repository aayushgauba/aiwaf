"""Django cache I/O only; native Rust owns form timing and logical expiry."""
import hashlib
import inspect
import math
import warnings

from django.conf import settings
from django.core.cache import caches
from django.core.cache.backends.dummy import DummyCache
from django.core.cache.backends.locmem import LocMemCache
from django.core.exceptions import ImproperlyConfigured


class DjangoHoneypotCache:
    def __init__(self, alias="default", *, validate_backend=True):
        if not isinstance(alias, str) or not alias.strip():
            raise ImproperlyConfigured("honeypot_cache_alias must name a configured Django cache")
        self.alias = alias
        if not validate_backend:
            return
        backend = caches[alias]
        if isinstance(backend, DummyCache):
            raise ImproperlyConfigured("Native honeypot timing cannot use Django DummyCache")
        options = settings.CACHES[alias].get("OPTIONS", {})
        if options.get("IGNORE_EXCEPTIONS", getattr(settings, "DJANGO_REDIS_IGNORE_EXCEPTIONS", False)) or options.get("ignore_exc"):
            raise ImproperlyConfigured("Native honeypot timing requires cache errors to propagate; disable ignored cache exceptions")
        if isinstance(backend, LocMemCache):
            warnings.warn("AIWAF honeypot timing uses Django LocMemCache, which is not shared across workers; configure a shared cache for multi-worker timing.", RuntimeWarning, stacklevel=2)

    @staticmethod
    def key(ip):
        # Bounded keys also work with Memcached and Django KEY_PREFIX/VERSION.
        return "aiwaf:native:honeypot:v1:" + hashlib.sha256(ip.encode("utf-8")).hexdigest()

    def get_timestamp(self, ip):
        value = caches[self.alias].get(self.key(ip))
        if inspect.isawaitable(value):
            if inspect.iscoroutine(value):
                value.close()
            raise RuntimeError("Honeypot cache methods must be synchronous")
        if value is None:
            return None
        if (not isinstance(value, (tuple, list)) or len(value) != 2 or
                any(isinstance(item, bool) or not isinstance(item, (int, float)) or not math.isfinite(item) for item in value)):
            raise RuntimeError("Invalid cached honeypot timestamp")
        return tuple(value)

    def set_timestamp(self, ip, timestamp, expires_at, ttl_seconds):
        result = caches[self.alias].set(self.key(ip), (timestamp, expires_at), timeout=ttl_seconds)
        if inspect.isawaitable(result):
            if inspect.iscoroutine(result):
                result.close()
            raise RuntimeError("Honeypot cache methods must be synchronous")
        if result is False:
            raise RuntimeError("Honeypot cache write failed")
