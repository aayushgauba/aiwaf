# Flask GeoBlockMiddleware
from flask import request, jsonify
from .utils import get_blocklist_extended_info, get_ip, is_exempt
from .blocklist_manager import BlocklistManager
from .exemption_decorators import should_apply_middleware
from .geoip import get_country_for_ip
from .storage import get_geo_blocked_countries
from aiwaf.core.geo_policy import GeoDecision, evaluate_geo_policy, normalize_country_list
from aiwaf.core.native_runtime import csv_function

_DEFAULT_GEO_POLICY = evaluate_geo_policy
_DEFAULT_GEO_STORE = get_geo_blocked_countries

def _normalize_country_list(value):
    return normalize_country_list(value)


class GeoBlockMiddleware:
    def __init__(self, app=None):
        self.app = app
        if app is not None:
            self.init_app(app)

    def init_app(self, app):
        @app.before_request
        def before_request():
            if not should_apply_middleware('geo_block'):
                return None

            if is_exempt(request):
                return None

            if not app.config.get('AIWAF_GEO_BLOCK_ENABLED', False):
                return None

            allow_countries = _normalize_country_list(
                app.config.get('AIWAF_GEO_ALLOW_COUNTRIES', [])
            )
            block_countries = _normalize_country_list(
                app.config.get('AIWAF_GEO_BLOCK_COUNTRIES', [])
            )
            from .storage import _get_storage_mode, _get_data_dir
            combined = (csv_function('csv_geo_policy') if (allow_countries or block_countries)
                and _get_storage_mode() == 'csv' and evaluate_geo_policy is _DEFAULT_GEO_POLICY
                and get_geo_blocked_countries is _DEFAULT_GEO_STORE else None)
            if combined is not None:
                from pathlib import Path
                from aiwaf.core import storage_csv_impl
                from aiwaf.core.storage_schema import GEO_BLOCKED_COUNTRIES_CSV
                directory = Path(_get_data_dir())
                storage_csv_impl.ensure_all(directory)
                ip = get_ip()
                country = get_country_for_ip(ip, app.config) if ip else ''
                decision = GeoDecision(*combined(str(directory / GEO_BLOCKED_COUNTRIES_CSV),
                    country or '', allow_countries, block_countries))
            else:
                dynamic_blocked = _normalize_country_list(get_geo_blocked_countries())

                if not allow_countries and not block_countries and not dynamic_blocked:
                    return None

                ip = get_ip()
                if not ip:
                    return None

                country = get_country_for_ip(ip, app.config)
                if not country:
                    return None

                decision = evaluate_geo_policy(
                    country=country,
                    allow_countries=allow_countries,
                    block_countries=block_countries,
                    dynamic_blocked=dynamic_blocked,
                )

            if decision.should_block:
                reason = decision.reason
                BlocklistManager.block(
                    ip,
                    reason,
                    extended_request_info=get_blocklist_extended_info(request),
                )

                logger = getattr(app, 'aiwaf_logger', None)
                if logger:
                    logger.mark_request_blocked(reason)

                return jsonify({"error": "blocked"}), 403

            return None


# Compatibility aliases for callers using the previous terminology.
get_blacklist_extended_info = get_blocklist_extended_info
BlacklistManager = BlocklistManager
