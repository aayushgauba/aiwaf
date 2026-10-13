"""FastAPI geo-block middleware."""

from starlette.middleware.base import BaseHTTPMiddleware
from fastapi.responses import JSONResponse

from ..blacklist import BlacklistManager
from ..decorators import should_apply_middleware
from ..geoip import get_country_for_ip
from ..storage import get_geo_block_store
from ..utils import get_blacklist_extended_info, get_ip, is_exempt
from aiwaf.core.geo_policy import evaluate_geo_policy, normalize_country_list
from aiwaf.core.runtime_storage import GeoBlockStore, CSVStorage
from aiwaf.core.policy_csv_storage import PolicyCSVStorage
from aiwaf.core.native_runtime import native_override

_DEFAULT_GEO_POLICY = evaluate_geo_policy


def _normalize_country_list(value):
    return normalize_country_list(value)


class GeoBlockMiddleware(BaseHTTPMiddleware):
    def __init__(self, app, enabled=False, allow_countries=None, block_countries=None, path_rules=None, use_rust=True):
        super().__init__(app)
        self.enabled = bool(enabled)
        self.allow_countries = _normalize_country_list(allow_countries or [])
        self.block_countries = _normalize_country_list(block_countries or [])
        self.path_rules = path_rules or []
        self.use_rust = bool(use_rust)

    async def dispatch(self, request, call_next):
        if not should_apply_middleware(request, "geo_block", self.path_rules):
            return await call_next(request)
        if is_exempt(request):
            return await call_next(request)
        if not self.enabled:
            return await call_next(request)

        store = get_geo_block_store()
        combined = (type(store) is GeoBlockStore and type(store.storage) in {CSVStorage, PolicyCSVStorage}
            and (self.allow_countries or self.block_countries)
            and evaluate_geo_policy is _DEFAULT_GEO_POLICY)
        with native_override(self.use_rust):
            dynamic_blocked = None if combined else store.get_countries()
        if not combined and not self.allow_countries and not self.block_countries and not dynamic_blocked:
            return await call_next(request)

        ip = get_ip(request)
        if not ip and not combined:
            return await call_next(request)
        country = (get_country_for_ip(ip) or "") if ip else ""
        if not country and not combined:
            return await call_next(request)

        if combined:
            with native_override(self.use_rust):
                decision = store.evaluate_geo_policy(country, self.allow_countries, self.block_countries)
        else:
            with native_override(self.use_rust):
                decision = evaluate_geo_policy(
                    country=country,
                    allow_countries=self.allow_countries,
                    block_countries=self.block_countries,
                    dynamic_blocked=dynamic_blocked,
                )

        if decision.should_block:
            reason = decision.reason
            BlacklistManager.block(ip, reason, extended_request_info=get_blacklist_extended_info(request))
            request.state.aiwaf_blocked = True
            request.state.aiwaf_block_reason = reason
            return JSONResponse({"error": "blocked"}, status_code=403)

        return await call_next(request)
