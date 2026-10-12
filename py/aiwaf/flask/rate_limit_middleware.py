# Flask-adapted RateLimitMiddleware
import time
from flask import request, jsonify, current_app
from .utils import get_blacklist_extended_info, get_ip, is_exempt
from .blacklist_manager import BlacklistManager
from .exemption_decorators import should_apply_middleware, get_path_rule_overrides
from aiwaf.core.exemptions import get_path_rule_for_path as core_get_path_rule_for_path
from aiwaf.core.block_responses import blocked_response, throttle_response
from aiwaf.core.cache_backend import CacheBackendConfig, DictCacheBackend, CSVRateCache, make_cache_backend
from aiwaf.core.rate_limit import (
    THROTTLE,
    FLOOD_BLOCK,
    build_rate_limit_key,
    consume_rate_limit,
    RateCacheUnavailable,
    normalize_rate_key_mode,
)

_aiwaf_cache = {}
_default_cache_backend = DictCacheBackend(_aiwaf_cache)

class RateLimitMiddleware:
    def __init__(self, app=None):
        self.app = app
        if app is not None:
            self.init_app(app)

    def init_app(self, app):
        if not getattr(app, "_aiwaf_rate_cache_backend", None):
            app._aiwaf_rate_cache_backend = _resolve_rate_cache_backend(app)
        if not getattr(app, "_aiwaf_rate_cache_key", None):
            # For shared backends (e.g., Redis), do not add a per-process salt;
            # we want multiple workers to hit the same bucket.
            backend = getattr(app, "_aiwaf_rate_cache_backend", _default_cache_backend)
            if getattr(backend, "is_shared", False):
                app._aiwaf_rate_cache_key = ""
            else:
                app._aiwaf_rate_cache_key = f"{id(app)}:{time.time_ns()}"

        @app.before_request
        def before_request():
            # Check exemption status first - skip if exempt from rate limiting
            if not should_apply_middleware('rate_limit'):
                return None  # Allow request to proceed without rate limiting

            # Legacy exemption check for backward compatibility
            if is_exempt(request):
                return None  # Allow request to proceed

            if request.environ.get("aiwaf_rate_limit_checked"):
                return None
            request.environ["aiwaf_rate_limit_checked"] = True
            
            ip = get_ip()
            app_key = app._aiwaf_rate_cache_key
            path = request.path or "unknown"
            key_mode = normalize_rate_key_mode(app.config.get("AIWAF_RATE_KEY_MODE", "ip_path"))
            key = build_rate_limit_key("ratelimit", ip, path, key_mode=key_mode, app_key=app_key)
            now = time.time()
            cache_backend = getattr(app, "_aiwaf_rate_cache_backend", _default_cache_backend)
            window = app.config.get("AIWAF_RATE_WINDOW", 10)
            max_req = app.config.get("AIWAF_RATE_MAX", 20)
            flood = app.config.get("AIWAF_RATE_FLOOD", 40)
            soft_block_blacklist = bool(app.config.get("AIWAF_RATE_SOFT_BLOCK_BLACKLIST", False))
            overrides = get_path_rule_overrides("RATE_LIMIT")
            if not overrides:
                overrides = _resolve_rate_limit_overrides(app, request.path)
            if overrides:
                window = overrides.get("WINDOW", window)
                max_req = overrides.get("MAX", max_req)
                flood = overrides.get("FLOOD", flood)

            try:
                decision = consume_rate_limit(
                    cache_backend, key,
                    now=now,
                    window_seconds=window,
                    max_requests=max_req,
                    flood_threshold=flood,
                )
            except RateCacheUnavailable:
                return jsonify({'error': 'temporarily_unavailable'}), 503

            if decision.action == FLOOD_BLOCK:
                BlacklistManager.block(
                    ip,
                    "Flood pattern",
                    extended_request_info=get_blacklist_extended_info(request),
                )
                payload, status = blocked_response()
                return jsonify(payload), status
            if decision.action == THROTTLE:
                if soft_block_blacklist:
                    BlacklistManager.block(
                        ip,
                        "Rate limit exceeded",
                        extended_request_info=get_blacklist_extended_info(request),
                    )
                payload, status = throttle_response()
                return jsonify(payload), status


def _resolve_rate_limit_overrides(app, path):
    try:
        rules = app.config.get("AIWAF_PATH_RULES")
        if rules is None:
            settings = app.config.get("AIWAF_SETTINGS", {})
            rules = settings.get("PATH_RULES")
        rules = rules or []
        best = core_get_path_rule_for_path(path, rules)
        if not best:
            return {}
        return best.get("RATE_LIMIT") or best.get("rate_limit") or {}
    except Exception:
        return {}


def _resolve_rate_cache_backend(app):
    backend = (app.config.get("AIWAF_RATE_CACHE_BACKEND") or "memory").strip().lower()
    if backend == "memory":
        return _default_cache_backend
    if backend == "csv":
        from pathlib import Path
        from .storage import _get_data_dir
        with app.app_context():
            path = app.config.get('AIWAF_RATE_CSV_PATH') or str(Path(_get_data_dir()) / 'rate_buckets.csv')
        return CSVRateCache(path)
    if backend == "redis":
        redis_url = app.config.get("AIWAF_REDIS_URL")
        key_prefix = app.config.get("AIWAF_RATE_CACHE_KEY_PREFIX", "aiwaf:rate:")
        return make_cache_backend(CacheBackendConfig(backend="redis", redis_url=redis_url, key_prefix=key_prefix))
    raise ValueError("Unknown AIWAF_RATE_CACHE_BACKEND")
