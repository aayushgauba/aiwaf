# Flask-adapted UUIDTamperMiddleware (stub)
from flask import request, jsonify, g, make_response
from .utils import get_blocklist_extended_info, get_ip
from .blocklist_manager import BlocklistManager
from .exemption_decorators import should_apply_middleware
from aiwaf.core.uuid_tamper import is_malformed_uuid, is_valid_uuid, record_uuid_signal

class UUIDTamperMiddleware:
    def __init__(self, app=None):
        self.app = app
        if app is not None:
            self.init_app(app)

    def init_app(self, app):
        def _score_config():
            return {
                "enabled": bool(app.config.get("AIWAF_UUID_SCORE_ENABLED", True)),
                "window_seconds": int(app.config.get("AIWAF_UUID_SCORE_WINDOW_SECONDS", 60)),
                "block_threshold": int(app.config.get("AIWAF_UUID_SCORE_BLOCK_THRESHOLD", 5)),
                "malformed_weight": int(app.config.get("AIWAF_UUID_SCORE_MALFORMED_WEIGHT", 5)),
                "not_found_weight": int(app.config.get("AIWAF_UUID_SCORE_NOT_FOUND_WEIGHT", 1)),
                "success_decay": int(app.config.get("AIWAF_UUID_SCORE_SUCCESS_DECAY", 2)),
            }

        @app.before_request
        def before_request():
            # Check exemption status first - skip if exempt from UUID tampering detection
            if not should_apply_middleware('uuid_tamper'):
                return None  # Allow request to proceed without UUID checking
            
            ip = get_ip()
            uuid_val = request.args.get("uuid")
            g.aiwaf_uuid_candidate = uuid_val
            g.aiwaf_uuid_ip = ip
            if is_malformed_uuid(uuid_val):
                decision = record_uuid_signal(ip, "malformed", config=_score_config())
                reason = f"UUID tampering score={decision['score']}"
                BlocklistManager.block(
                    ip,
                    reason,
                    extended_request_info=get_blocklist_extended_info(request),
                )
                return jsonify({"error": "blocked"}), 403

        @app.after_request
        def after_request(response):
            if not should_apply_middleware('uuid_tamper'):
                return response
            uuid_val = getattr(g, "aiwaf_uuid_candidate", None)
            ip = getattr(g, "aiwaf_uuid_ip", get_ip())
            if not is_valid_uuid(uuid_val):
                return response
            if response.status_code == 404:
                decision = record_uuid_signal(ip, "not_found", config=_score_config())
                if decision["blocked"]:
                    reason = f"UUID tampering score={decision['score']}"
                    BlocklistManager.block(
                        ip,
                        reason,
                        extended_request_info=get_blocklist_extended_info(request),
                    )
                    return make_response(jsonify({"error": "blocked"}), 403)
            elif response.status_code < 400:
                record_uuid_signal(ip, "success", config=_score_config())
            return response


# Compatibility aliases for callers using the previous terminology.
get_blacklist_extended_info = get_blocklist_extended_info
BlacklistManager = BlocklistManager
