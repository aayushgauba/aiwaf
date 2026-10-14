"""FastAPI honeypot timing middleware."""

import time
from starlette.middleware.base import BaseHTTPMiddleware
from fastapi.responses import JSONResponse

from ..blocklist import BlocklistManager
from ..decorators import should_apply_middleware
from ..utils import get_blocklist_extended_info, get_ip
from ...core.runtime_storage import get_storage
from ...core.honeypot import (
    store_honeypot_get_timestamp,
    load_honeypot_get_timestamp,
    clear_honeypot_get_timestamp,
    evaluate_form_timing,
    is_authenticated_session_context,
    ACTION_BLOCK,
    ACTION_PAGE_EXPIRED,
)
from ...core.method_validation import evaluate_method_policy, ACTION_BLOCK as METHOD_BLOCK
from ...core.method_validation import fastapi_route_accepts_method

class _HoneypotStateCache:
    def __setitem__(self, key, value):
        get_storage().set(key, value, ttl=300)

    def get(self, key, default=None):
        value = get_storage().get(key)
        return default if value is None else value

    def pop(self, key, default=None):
        value = get_storage().get(key)
        get_storage().delete(key)
        return default if value is None else value

    def clear(self):
        storage = get_storage()
        for key in storage.get_all_keys("honeypot_get:*"):
            storage.delete(key)


_AIWAF_CACHE = _HoneypotStateCache()


class HoneypotTimingMiddleware(BaseHTTPMiddleware):
    def __init__(self, app, min_form_time=1.0, max_page_time=240, skip_authenticated=True, path_rules=None):
        super().__init__(app)
        self.min_form_time = float(min_form_time)
        self.max_page_time = float(max_page_time)
        self.skip_authenticated = bool(skip_authenticated)
        self.path_rules = path_rules or []

    async def dispatch(self, request, call_next):
        if not should_apply_middleware(request, "honeypot", self.path_rules):
            return await call_next(request)

        if self.skip_authenticated and self._is_authenticated_request(request):
            return await call_next(request)

        ip = get_ip(request)
        now = time.time()

        method_decision = evaluate_method_policy(
            method=request.method,
            path=request.url.path,
            accepts_get=fastapi_route_accepts_method(request, "GET"),
            accepts_post=fastapi_route_accepts_method(request, "POST"),
            accepts_method=fastapi_route_accepts_method(request, request.method),
        )
        if method_decision.action == METHOD_BLOCK:
            BlocklistManager.block(
                ip,
                method_decision.reason,
                extended_request_info=get_blocklist_extended_info(request),
            )
            request.state.aiwaf_blocked = True
            request.state.aiwaf_block_reason = method_decision.message or "method not allowed"
            return JSONResponse({"error": "blocked", "message": method_decision.message}, status_code=method_decision.status_code)

        if request.method == "GET":
            store_honeypot_get_timestamp(
                lambda key, value, _ttl: _AIWAF_CACHE.__setitem__(key, value),
                ip,
                now,
            )
        elif request.method == "POST":
            decision = evaluate_form_timing(
                now=now,
                get_time=load_honeypot_get_timestamp(_AIWAF_CACHE.get, ip),
                path=request.url.path,
                min_form_time=self.min_form_time,
                max_page_time=self.max_page_time,
            )
            if decision.action == ACTION_PAGE_EXPIRED:
                clear_honeypot_get_timestamp(lambda key: _AIWAF_CACHE.pop(key, None), ip)
                return JSONResponse(
                    {
                        "error": "page_expired",
                        "message": decision.message or "Page has expired. Please reload and try again.",
                        "reload_required": True,
                    },
                    status_code=decision.status_code or 409,
                )
            if decision.action == ACTION_BLOCK:
                BlocklistManager.block(
                    ip,
                    decision.reason or "Form submitted too quickly",
                    extended_request_info=get_blocklist_extended_info(request),
                )
                request.state.aiwaf_blocked = True
                request.state.aiwaf_block_reason = "honeypot"
                return JSONResponse({"error": "blocked"}, status_code=decision.status_code or 403)

        return await call_next(request)

    def _is_authenticated_request(self, request) -> bool:
        user = None
        session = None
        try:
            user = request.scope.get("user") if hasattr(request, "scope") else None
        except Exception:
            user = None
        try:
            session = request.session  # available when SessionMiddleware is installed
        except Exception:
            session = None
        return is_authenticated_session_context(user=user, session=session)


# Compatibility aliases for callers using the previous terminology.
BlacklistManager = BlocklistManager
get_blacklist_extended_info = get_blocklist_extended_info
