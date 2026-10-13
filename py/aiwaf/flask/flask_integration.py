from __future__ import annotations

from typing import Iterable

from .ip_and_keyword_block_middleware import IPAndKeywordBlockMiddleware
from .rate_limit_middleware import RateLimitMiddleware
from .honeypot_timing_middleware import HoneypotTimingMiddleware
from .header_validation_middleware import HeaderValidationMiddleware
from .anomaly_middleware import AIAnomalyMiddleware
from .uuid_tamper_middleware import UUIDTamperMiddleware
from .logging_middleware import AIWAFLoggingMiddleware
from .geo_block_middleware import GeoBlockMiddleware
from aiwaf.core.middleware_plan import plan_enabled_middlewares
from aiwaf.core.middleware_plan import should_enable_geo
from aiwaf.core.route_capabilities import detect_uuid_routes_in_flask_app
from .storage import get_geo_blocked_countries


class AIWAF:
    AVAILABLE_MIDDLEWARES = {
        # Keep registration order aligned with Django chain semantics.
        "geo_block": GeoBlockMiddleware,
        "ip_keyword_block": IPAndKeywordBlockMiddleware,
        "rate_limit": RateLimitMiddleware,
        "ai_anomaly": AIAnomalyMiddleware,
        "honeypot": HoneypotTimingMiddleware,
        "uuid_tamper": UUIDTamperMiddleware,
        "header_validation": HeaderValidationMiddleware,
        "logging": AIWAFLoggingMiddleware,
    }

    def __init__(self, app=None, middlewares: Iterable[str] | None = None, disable_middlewares: Iterable[str] | None = None, use_database=None):
        self.app = None
        self.middleware_instances = {}
        self.enabled_middlewares = set()
        if app is not None:
            self.init_app(app, middlewares=middlewares, disable_middlewares=disable_middlewares, use_database=use_database)

    @classmethod
    def list_available_middlewares(cls):
        return list(cls.AVAILABLE_MIDDLEWARES.keys())

    def get_enabled_middlewares(self):
        return list(self.enabled_middlewares)

    def is_middleware_enabled(self, name: str) -> bool:
        return name in self.enabled_middlewares

    def _resolve_middlewares(self, middlewares, disable_middlewares):
        all_keys = list(self.AVAILABLE_MIDDLEWARES.keys())
        access_log = self.app.config.get("AIWAF_ACCESS_LOG") if self.app is not None else None
        geo_enabled_flag = bool(self.app.config.get("AIWAF_GEO_BLOCK_ENABLED", False)) if self.app is not None else False
        static_block = self.app.config.get("AIWAF_GEO_BLOCK_COUNTRIES", []) if self.app is not None else []
        dynamic_block = get_geo_blocked_countries() if self.app is not None else []
        return plan_enabled_middlewares(
            ordered_available=all_keys,
            requested=middlewares,
            disabled=disable_middlewares,
            access_log=access_log,
            geo_enabled_flag=geo_enabled_flag,
            static_block_countries=static_block,
            dynamic_block_countries=dynamic_block,
            has_uuid_routes=detect_uuid_routes_in_flask_app(self.app),
        )

    def init_app(self, app, middlewares: Iterable[str] | None = None, disable_middlewares: Iterable[str] | None = None, use_database=None):
        self.app = app
        if app.config.get('AIWAF_USE_CSV', True) and use_database is not True:
            from aiwaf.core.policy_csv_storage import PolicyCSVStorage
            from .storage import _get_data_dir
            with app.app_context():
                app.extensions['aiwaf_policy_storage'] = PolicyCSVStorage(data_dir=_get_data_dir())
        enabled = self._resolve_middlewares(middlewares, disable_middlewares)
        self.enabled_middlewares = set(enabled)
        if "geo_block" in enabled and not app.config.get("AIWAF_GEO_BLOCK_ENABLED", False):
            app.config["AIWAF_GEO_BLOCK_ENABLED"] = should_enable_geo(
                geo_enabled_flag=bool(app.config.get("AIWAF_GEO_BLOCK_ENABLED", False)),
                static_block_countries=app.config.get("AIWAF_GEO_BLOCK_COUNTRIES", []) or [],
                dynamic_block_countries=get_geo_blocked_countries(),
            )

        # ensure database initialized when requested
        if use_database is True:
            from .middleware import _init_database
            _init_database(app)

        for name in self.AVAILABLE_MIDDLEWARES:
            if name not in enabled:
                continue
            middleware_cls = self.AVAILABLE_MIDDLEWARES[name]
            instance = middleware_cls(app)
            self.middleware_instances[name] = instance

        app.extensions = getattr(app, "extensions", {})
        app.extensions["aiwaf"] = self
        return self
