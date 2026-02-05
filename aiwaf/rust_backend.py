"""
Optional Rust backend for header validation and CSV logging.
Falls back to Python if the Rust extension is unavailable.
"""

from __future__ import annotations

try:
    import aiwaf_rust  # Built via maturin/pyo3
except Exception:
    aiwaf_rust = None


def rust_available() -> bool:
    return aiwaf_rust is not None


def validate_headers(headers, required_headers=None, min_score=None) -> str | None:
    if aiwaf_rust is None:
        return None
    try:
        if hasattr(aiwaf_rust, "validate_headers_with_config"):
            return aiwaf_rust.validate_headers_with_config(
                headers,
                required_headers,
                min_score,
            )
        return aiwaf_rust.validate_headers(headers)
    except Exception:
        return None


def extract_features(records, static_keywords):
    if aiwaf_rust is None:
        return None
    try:
        return aiwaf_rust.extract_features(records, static_keywords)
    except Exception:
        return None


def analyze_recent_behavior(entries, static_keywords):
    if aiwaf_rust is None:
        return None
    try:
        return aiwaf_rust.analyze_recent_behavior(entries, static_keywords)
    except Exception:
        return None
