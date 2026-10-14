# Flask-adapted HoneypotTimingMiddleware
import time
from flask import request, jsonify, current_app
from .utils import get_blocklist_extended_info, get_ip
from .blocklist_manager import BlocklistManager
from .exemption_decorators import should_apply_middleware
from aiwaf.core.runtime_storage import get_storage
from aiwaf.core.honeypot import (
    store_honeypot_get_timestamp,
    load_honeypot_get_timestamp,
    clear_honeypot_get_timestamp,
    evaluate_form_timing,
    ACTION_BLOCK,
    ACTION_PAGE_EXPIRED,
)
from aiwaf.core.method_validation import evaluate_method_policy, ACTION_BLOCK as METHOD_BLOCK
from aiwaf.core.method_validation import flask_route_accepts_method

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


_aiwaf_cache = _HoneypotStateCache()


def _is_authenticated_request() -> bool:
    """Best-effort auth detection without introducing hard dependencies."""
    try:
        from flask_login import current_user  # type: ignore

        return bool(getattr(current_user, "is_authenticated", False))
    except Exception:
        return False


class HoneypotTimingMiddleware:
    def __init__(self, app=None):
        self.app = app
        if app is not None:
            self.init_app(app)

    def init_app(self, app):
        def _view_accepts_method(method: str) -> bool:
            return flask_route_accepts_method(app, request.path, method)

        @app.before_request
        def before_request():
            # Check exemption status first - skip if exempt from honeypot detection
            if not should_apply_middleware('honeypot'):
                return None  # Allow request to proceed without honeypot timing checks

            if app.config.get("AIWAF_HONEYPOT_SKIP_AUTHENTICATED", True) and _is_authenticated_request():
                return None
            
            ip = get_ip()
            now = time.time()
            decision = evaluate_method_policy(
                method=request.method,
                path=request.path,
                accepts_get=_view_accepts_method("GET"),
                accepts_post=_view_accepts_method("POST"),
                accepts_method=_view_accepts_method(request.method),
            )
            if decision.action == METHOD_BLOCK:
                BlocklistManager.block(
                    ip,
                    decision.reason,
                    extended_request_info=get_blocklist_extended_info(request),
                )
                return jsonify({"error": "blocked", "message": decision.message}), decision.status_code

            if request.method == "GET":
                store_honeypot_get_timestamp(
                    lambda key, value, _ttl: _aiwaf_cache.__setitem__(key, value),
                    ip,
                    now,
                )
            elif request.method == "POST":
                decision = evaluate_form_timing(
                    now=now,
                    get_time=load_honeypot_get_timestamp(_aiwaf_cache.get, ip),
                    path=request.path,
                    min_form_time=app.config.get("AIWAF_MIN_FORM_TIME", 1.0),
                    max_page_time=app.config.get("AIWAF_MAX_PAGE_TIME", 240),
                )
                if decision.action == ACTION_PAGE_EXPIRED:
                    clear_honeypot_get_timestamp(lambda key: _aiwaf_cache.pop(key, None), ip)
                    return jsonify(
                        {
                            "error": "page_expired",
                            "message": decision.message or "Page has expired. Please reload and try again.",
                            "reload_required": True,
                        }
                    ), (decision.status_code or 409)
                if decision.action == ACTION_BLOCK:
                    BlocklistManager.block(
                        ip,
                        decision.reason or "Form submitted too quickly",
                        extended_request_info=get_blocklist_extended_info(request),
                    )
                    return jsonify({"error": "blocked"}), (decision.status_code or 403)


# Compatibility aliases for callers using the previous terminology.
get_blacklist_extended_info = get_blocklist_extended_info
BlacklistManager = BlocklistManager
