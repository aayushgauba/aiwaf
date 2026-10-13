"""
AIWAF Flask entrypoint.

Usage:
    import aiwaf.flask as aiwaf
"""

from importlib import import_module

__all__ = [
    "NativeAIWAF",
    "AIWAF",
    "register_aiwaf_middlewares",
    "register_aiwaf_protection",
    "IPAndKeywordBlockMiddleware",
    "RateLimitMiddleware",
    "HoneypotTimingMiddleware",
    "HeaderValidationMiddleware",
    "AIAnomalyMiddleware",
    "UUIDTamperMiddleware",
    "GeoBlockMiddleware",
    "AIWAFLoggingMiddleware",
    "AIWAFLoggerMiddleware",
    "analyze_access_logs",
    "aiwaf_exempt",
    "aiwaf_exempt_from",
    "aiwaf_only",
    "aiwaf_require_protection",
    "is_request_exempt",
    "should_apply_middleware",
    "AIWAFManager",
]


def _load_middleware():
    return import_module(".middleware", __name__)


def _load_logging():
    return import_module(".logging_middleware", __name__)


def _load_logger():
    return import_module(".middleware_logger", __name__)


def _load_decorators():
    return import_module(".exemption_decorators", __name__)


def _load_integration():
    return import_module(".flask_integration", __name__)


def __getattr__(name):
    if name == "NativeAIWAF":
        return getattr(import_module(".csv_pipeline", __name__), name)
    if name == "AIWAF":
        return getattr(_load_integration(), "AIWAF")
    if name == "register_aiwaf_middlewares":
        return getattr(_load_middleware(), "register_aiwaf_middlewares")
    if name == "register_aiwaf_protection":
        return getattr(_load_middleware(), "register_aiwaf_middlewares")
    if name in {
        "IPAndKeywordBlockMiddleware",
        "RateLimitMiddleware",
        "HoneypotTimingMiddleware",
        "HeaderValidationMiddleware",
        "AIAnomalyMiddleware",
        "UUIDTamperMiddleware",
        "GeoBlockMiddleware",
    }:
        module_map = {
            "IPAndKeywordBlockMiddleware": ".ip_and_keyword_block_middleware",
            "RateLimitMiddleware": ".rate_limit_middleware",
            "HoneypotTimingMiddleware": ".honeypot_timing_middleware",
            "HeaderValidationMiddleware": ".header_validation_middleware",
            "AIAnomalyMiddleware": ".anomaly_middleware",
            "UUIDTamperMiddleware": ".uuid_tamper_middleware",
            "GeoBlockMiddleware": ".geo_block_middleware",
        }
        module = import_module(module_map[name], __name__)
        return getattr(module, name)
    if name in {"AIWAFLoggingMiddleware", "analyze_access_logs"}:
        return getattr(_load_logging(), name)
    if name == "AIWAFLoggerMiddleware":
        return getattr(_load_logger(), name)
    if name in {
        "aiwaf_exempt",
        "aiwaf_exempt_from",
        "aiwaf_only",
        "aiwaf_require_protection",
        "is_request_exempt",
        "should_apply_middleware",
    }:
        return getattr(_load_decorators(), name)
    if name == "AIWAFManager":
        try:
            return getattr(import_module(".cli", __name__), "AIWAFManager")
        except Exception:
            return None
    raise AttributeError(f"module {__name__!r} has no attribute {name!r}")
