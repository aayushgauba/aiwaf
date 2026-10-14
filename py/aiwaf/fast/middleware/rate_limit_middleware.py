"""FastAPI rate-limit middleware."""

import time
from starlette.middleware.base import BaseHTTPMiddleware
from fastapi.responses import JSONResponse

from ..blocklist import BlocklistManager
from ..decorators import get_path_rule_overrides, should_apply_middleware
from ..utils import get_blocklist_extended_info, get_ip, is_exempt
from ...core.cache_backend import (
    CacheBackend,
    CacheBackendConfig,
    DictCacheBackend,
    make_cache_backend,
)
from ...core.rate_limit import (
    THROTTLE,
    FLOOD_BLOCK,
    build_rate_limit_key,
    consume_rate_limit,
    RateCacheUnavailable,
    normalize_rate_key_mode,
)
from ...core.block_responses import blocked_response, throttle_response

_AIWAF_CACHE: dict = {}
_DEFAULT_CACHE_BACKEND: CacheBackend = DictCacheBackend(_AIWAF_CACHE)


class RateLimitMiddleware(BaseHTTPMiddleware):
    def __init__(
        self,
        app,
        max_requests=20,
        window_seconds=10,
        flood_threshold=40,
        path_rules=None,
        key_mode="ip_path",
        soft_block_blocklist=False,
        cache_backend: CacheBackend | None = None,
    ):
        super().__init__(app)
        self.max_requests = max_requests
        self.window_seconds = window_seconds
        self.flood_threshold = flood_threshold
        self.path_rules = path_rules or []
        self.key_mode = normalize_rate_key_mode(key_mode)
        self.soft_block_blocklist = bool(soft_block_blocklist)
        self.cache_backend = cache_backend
        self._explicit_cache_backend = cache_backend is not None
        self._initial_app = app
        self._runtime_bound = False
        # Initialize lazily (some Starlette stacks pass a wrapped app lacking `.state`).
        self._init_from_app(app)

    def _init_from_app(self, app):
        if self.cache_backend is None:
            self.cache_backend = self._resolve_cache_backend(app)
        # For shared backends (e.g., Redis), do not add a per-process salt;
        # we want multiple workers to hit the same bucket.
        self.app_key = "" if getattr(self.cache_backend, "is_shared", False) else f"{id(app)}:{time.time_ns()}"

    def _resolve_cache_backend(self, app) -> CacheBackend:
        # Prefer app.state config when available (AIWAF runtime attaches it).
        cfg = None
        try:
            state = getattr(app, "state", None)
            cfg = getattr(state, "aiwaf_config", None)
        except Exception:
            cfg = None

        backend = None
        redis_url = None
        key_prefix = "aiwaf:rate:"
        if cfg is not None:
            try:
                backend = cfg.get("rate_limiting.cache_backend", None) or cfg.get("AIWAF_RATE_CACHE_BACKEND", None)
                redis_url = cfg.get("rate_limiting.redis_url", None) or cfg.get("AIWAF_REDIS_URL", None)
                key_prefix = cfg.get("rate_limiting.cache_key_prefix", key_prefix) or key_prefix
            except Exception:
                pass

        if backend:
            return make_cache_backend(CacheBackendConfig(backend=str(backend), redis_url=redis_url, key_prefix=str(key_prefix)))

        return _DEFAULT_CACHE_BACKEND

    async def dispatch(self, request, call_next):
        # Ensure cache backend is resolved against the actual FastAPI app when possible.
        try:
            candidate_apps = []
            req_app = getattr(request, "app", None)
            if req_app is not None:
                candidate_apps.append(req_app)
            scope_app = request.scope.get("app") if hasattr(request, "scope") else None
            if scope_app is not None:
                candidate_apps.append(scope_app)

            for candidate in candidate_apps:
                state = getattr(candidate, "state", None)
                cfg = getattr(state, "aiwaf_config", None) if state is not None else None
                if cfg is None:
                    continue
                if not self._runtime_bound and not self._explicit_cache_backend:
                    self.cache_backend = None
                    self._init_from_app(candidate)
                    self._runtime_bound = True
                    break
        except Exception:
            return JSONResponse({'error': 'temporarily_unavailable'}, status_code=503)

        if not should_apply_middleware(request, "rate_limit", self.path_rules):
            return await call_next(request)
        if is_exempt(request):
            return await call_next(request)

        ip = get_ip(request)
        path = request.url.path or "unknown"
        key = build_rate_limit_key("ratelimit", ip, path, key_mode=self.key_mode, app_key=self.app_key)
        now = time.time()

        window = self.window_seconds
        max_req = self.max_requests
        flood = self.flood_threshold
        overrides = get_path_rule_overrides(request, "RATE_LIMIT", self.path_rules)
        if overrides:
            window = int(overrides.get("WINDOW", window))
            max_req = int(overrides.get("MAX", max_req))
            flood = int(overrides.get("FLOOD", flood))

        try:
            decision = consume_rate_limit(
                self.cache_backend or _DEFAULT_CACHE_BACKEND, key,
                now=now,
                window_seconds=window,
                max_requests=max_req,
                flood_threshold=flood,
            )
        except RateCacheUnavailable:
            request.state.aiwaf_blocked = True
            request.state.aiwaf_block_reason = 'Rate cache unavailable'
            return JSONResponse({'error': 'temporarily_unavailable'}, status_code=503)

        if decision.action == FLOOD_BLOCK:
            BlocklistManager.block(ip, "Flood pattern", extended_request_info=get_blocklist_extended_info(request))
            request.state.aiwaf_blocked = True
            request.state.aiwaf_block_reason = "Flood pattern"
            payload, status = blocked_response()
            return JSONResponse(payload, status_code=status)
        if decision.action == THROTTLE:
            if self.soft_block_blocklist:
                BlocklistManager.block(
                    ip,
                    "Rate limit exceeded",
                    extended_request_info=get_blocklist_extended_info(request),
                )
            request.state.aiwaf_blocked = True
            request.state.aiwaf_block_reason = "Rate limit exceeded"
            payload, status = throttle_response()
            return JSONResponse(payload, status_code=status)

        return await call_next(request)


# Compatibility aliases for callers using the previous terminology.
BlacklistManager = BlocklistManager
get_blacklist_extended_info = get_blocklist_extended_info
