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


def validate_headers(headers) -> str | None:
    if aiwaf_rust is None:
        return None
    try:
        return aiwaf_rust.validate_headers(headers)
    except Exception:
        return None

