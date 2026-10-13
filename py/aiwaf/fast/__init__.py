"""
AIWAF FastAPI entrypoint.

Usage:
    import aiwaf.fast as aiwaf
"""

from importlib import import_module

from aiwaf import __version__

__all__ = [
    "NativeAIWAFMiddleware",
    "AIWAF",
    "AIWAFConfig",
    "IPAndKeywordBlockMiddleware",
    "RateLimitMiddleware",
    "HoneypotTimingMiddleware",
    "HeaderValidationMiddleware",
    "GeoBlockMiddleware",
    "AIAnomalyMiddleware",
    "UUIDTamperMiddleware",
    "AIWAFLoggingMiddleware",
    "aiwaf_exempt",
    "aiwaf_exempt_from",
    "aiwaf_only",
    "aiwaf_require_protection",
    "should_apply_middleware",
    "get_path_rule_overrides",
]


def __getattr__(name):
    if name == "NativeAIWAFMiddleware":
        return getattr(import_module(".csv_pipeline", __name__), name)
    if name == "AIWAF":
        return getattr(import_module(".core", __name__), name)
    if name == "AIWAFConfig":
        return getattr(import_module(".config", __name__), name)
    if name in {
        "IPAndKeywordBlockMiddleware",
        "RateLimitMiddleware",
        "HoneypotTimingMiddleware",
        "HeaderValidationMiddleware",
        "GeoBlockMiddleware",
        "AIAnomalyMiddleware",
        "UUIDTamperMiddleware",
        "AIWAFLoggingMiddleware",
    }:
        return getattr(import_module(".middleware", __name__), name)
    if name in {
        "aiwaf_exempt",
        "aiwaf_exempt_from",
        "aiwaf_only",
        "aiwaf_require_protection",
        "should_apply_middleware",
        "get_path_rule_overrides",
    }:
        return getattr(import_module(".decorators", __name__), name)
    raise AttributeError(f"module {__name__!r} has no attribute {name!r}")
