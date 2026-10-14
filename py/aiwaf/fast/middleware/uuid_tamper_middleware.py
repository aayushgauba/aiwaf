"""FastAPI UUID tamper middleware."""
from starlette.middleware.base import BaseHTTPMiddleware
from fastapi.responses import JSONResponse

from ..blocklist import BlocklistManager
from ..decorators import should_apply_middleware
from ..utils import get_blocklist_extended_info, get_ip
from ...core.uuid_tamper import is_malformed_uuid, is_valid_uuid, record_uuid_signal


class UUIDTamperMiddleware(BaseHTTPMiddleware):
    def __init__(self, app, path_rules=None):
        super().__init__(app)
        self.path_rules = path_rules or []

    async def dispatch(self, request, call_next):
        if not should_apply_middleware(request, "uuid_tamper", self.path_rules):
            return await call_next(request)

        ip = get_ip(request)
        uuid_val = request.query_params.get("uuid")
        cfg = getattr(request.app.state, "aiwaf_config", None)

        def _cfg(key, default):
            if cfg is None or not hasattr(cfg, "get"):
                return default
            try:
                return cfg.get(key, default)
            except Exception:
                return default

        score_cfg = {
            "enabled": bool(_cfg("AIWAF_UUID_SCORE_ENABLED", True)),
            "window_seconds": int(_cfg("AIWAF_UUID_SCORE_WINDOW_SECONDS", 60)),
            "block_threshold": int(_cfg("AIWAF_UUID_SCORE_BLOCK_THRESHOLD", 5)),
            "malformed_weight": int(_cfg("AIWAF_UUID_SCORE_MALFORMED_WEIGHT", 5)),
            "not_found_weight": int(_cfg("AIWAF_UUID_SCORE_NOT_FOUND_WEIGHT", 1)),
            "success_decay": int(_cfg("AIWAF_UUID_SCORE_SUCCESS_DECAY", 2)),
        }

        if is_malformed_uuid(uuid_val):
            decision = record_uuid_signal(ip, "malformed", config=score_cfg)
            reason = f"UUID tampering score={decision['score']}"
            BlocklistManager.block(ip, reason, extended_request_info=get_blocklist_extended_info(request))
            request.state.aiwaf_blocked = True
            request.state.aiwaf_block_reason = reason
            return JSONResponse({"error": "blocked"}, status_code=403)

        response = await call_next(request)
        if is_valid_uuid(uuid_val):
            if response.status_code == 404:
                decision = record_uuid_signal(ip, "not_found", config=score_cfg)
                if decision["blocked"]:
                    reason = f"UUID tampering score={decision['score']}"
                    BlocklistManager.block(
                        ip,
                        reason,
                        extended_request_info=get_blocklist_extended_info(request),
                    )
                    request.state.aiwaf_blocked = True
                    request.state.aiwaf_block_reason = reason
                    return JSONResponse({"error": "blocked"}, status_code=403)
            elif response.status_code < 400:
                record_uuid_signal(ip, "success", config=score_cfg)
        return response


# Compatibility aliases for callers using the previous terminology.
BlacklistManager = BlocklistManager
get_blacklist_extended_info = get_blocklist_extended_info
