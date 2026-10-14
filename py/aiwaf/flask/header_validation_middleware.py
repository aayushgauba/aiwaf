# Flask-adapted HeaderValidationMiddleware
import re
from flask import request, jsonify, current_app
from .utils import get_blocklist_extended_info, get_ip, is_exempt
from .blocklist_manager import BlocklistManager
from .exemption_decorators import should_apply_middleware
from aiwaf.core import rust_backend
from aiwaf.core import header_validation

def _get_min_quality_score(config_required_headers=None, method=None):
    default_min = current_app.config.get("AIWAF_HEADER_QUALITY_MIN_SCORE", 3)
    required_headers = header_validation.resolve_required_headers(config_required_headers, method)
    if not required_headers:
        return 0
    return default_min

class HeaderValidationMiddleware:
    def __init__(self, app=None):
        self.app = app
        if app is not None:
            self.init_app(app)

    def init_app(self, app):
        @app.before_request
        def before_request():
            # Check exemption status first - skip if exempt from header validation
            if not should_apply_middleware('header_validation'):
                return None  # Allow request to proceed without header validation
            
            # Legacy exemption check for backward compatibility
            if is_exempt(request):
                return None  # Allow request to proceed
            
            ip = get_ip()
            req_method = (request.method or "GET").upper()
            configured_required = current_app.config.get("AIWAF_REQUIRED_HEADERS")

            effective_required_headers = header_validation.resolve_required_headers(configured_required, req_method)
            min_score = _get_min_quality_score(configured_required, req_method)

            used_rust, reason = rust_backend.evaluate_headers_full_default(
                request.environ, effective_required_headers, min_score
            )
            if not used_rust:
                reason = header_validation.evaluate_header_policy(
                    request.environ,
                    method=req_method,
                    config_required_headers=configured_required,
                    min_score=min_score,
                )

            if reason:
                BlocklistManager.block(
                    ip,
                    reason,
                    extended_request_info=get_blocklist_extended_info(request),
                )
                logger = getattr(current_app, "aiwaf_logger", None)
                if logger is not None:
                    logger.mark_request_blocked(reason)
                return jsonify({"error": "blocked"}), 403


# Compatibility aliases for callers using the previous terminology.
get_blacklist_extended_info = get_blocklist_extended_info
BlacklistManager = BlocklistManager
