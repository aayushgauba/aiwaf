"""
Rust dispatch for compatibility adapters.
Python 1.1.3 requires the native package at installation. Legacy adapters retain
guarded Python paths for custom integrations; CSVPipeline requires native support.
"""

from __future__ import annotations

try:
    import aiwaf_rust  # Built via maturin/pyo3
except Exception:
    aiwaf_rust = None


def rust_available() -> bool:
    return aiwaf_rust is not None


def rust_isolation_forest_available() -> bool:
    return aiwaf_rust is not None and hasattr(aiwaf_rust, "IsolationForest")


def rust_isolation_forest_class():
    if aiwaf_rust is None:
        return None
    return getattr(aiwaf_rust, "IsolationForest", None)


def is_rust_isolation_forest(obj) -> bool:
    if aiwaf_rust is None or obj is None:
        return False
    rust_cls = getattr(aiwaf_rust, "IsolationForest", None)
    if rust_cls is None:
        return False
    return isinstance(obj, rust_cls)


def rust_isolation_forest_from_json(state):
    if aiwaf_rust is None or not hasattr(aiwaf_rust, "IsolationForest"):
        return None
    try:
        return aiwaf_rust.IsolationForest.from_json(state)
    except Exception:
        return None


def _to_rust_header_name(name):
    """Accept both HTTP header names and WSGI environ keys."""
    name = str(name).upper().replace("-", "_")
    if name.startswith("HTTP_") or name in {"CONTENT_TYPE", "CONTENT_LENGTH", "SERVER_PROTOCOL"}:
        return name
    return f"HTTP_{name}"


def validate_headers(headers, required_headers=None, min_score=None) -> str | None:
    if aiwaf_rust is None:
        return None
    try:
        rust_headers = {_to_rust_header_name(key): value for key, value in headers.items()}
        rust_required = (
            [_to_rust_header_name(name) for name in required_headers]
            if required_headers is not None else None
        )
        if hasattr(aiwaf_rust, "validate_headers_with_config"):
            return aiwaf_rust.validate_headers_with_config(
                rust_headers,
                rust_required,
                min_score,
            )
        return aiwaf_rust.validate_headers(rust_headers)
    except Exception:
        return None


def evaluate_headers_full_default(headers, required_headers, min_score):
    """Return (used_rust, reason); distinguish a clean pass from backend failure."""
    evaluator = getattr(aiwaf_rust, "validate_headers_full_default", None) if aiwaf_rust else None
    if evaluator is None:
        return False, None
    try:
        return True, evaluator(headers, required_headers, int(min_score))
    except Exception:
        return False, None


def extract_features(records, static_keywords):
    if aiwaf_rust is None:
        return None
    try:
        return aiwaf_rust.extract_features(records, static_keywords)
    except Exception:
        return None


def build_records(parsed, ip_404, path_exists_fn, path_exempt_fn, status_idx_list):
    if aiwaf_rust is None or not hasattr(aiwaf_rust, "build_records"):
        return None
    try:
        return aiwaf_rust.build_records(parsed, ip_404, path_exists_fn, path_exempt_fn, status_idx_list)
    except Exception:
        return None


def supports_raw_feature_extraction() -> bool:
    return aiwaf_rust is not None and hasattr(aiwaf_rust, "extract_raw_features")


def extract_raw_features(parsed, eligible_paths, ip_404, status_idx_list, static_keywords):
    if not supports_raw_feature_extraction():
        return None
    try:
        return aiwaf_rust.extract_raw_features(
            parsed, eligible_paths, ip_404, [str(status) for status in status_idx_list], static_keywords
        )
    except Exception:
        return None


def rust_payload_from_records(records):
    if aiwaf_rust is None or not hasattr(aiwaf_rust, "rust_payload_from_records"):
        return None
    try:
        return aiwaf_rust.rust_payload_from_records(records)
    except Exception:
        return None


def python_feature_from_record(record, ip_times, static_keywords):
    if aiwaf_rust is None or not hasattr(aiwaf_rust, "python_feature_from_record"):
        return None
    try:
        return aiwaf_rust.python_feature_from_record(record, ip_times, static_keywords)
    except Exception:
        return None


def python_features_batched(
    records,
    ip_times,
    static_keywords,
    iter_batches_fn,
    batch_size,
    parallel_enabled,
    parallel_chunk_size,
    max_workers,
):
    if aiwaf_rust is None or not hasattr(aiwaf_rust, "python_features_batched"):
        return None
    try:
        return aiwaf_rust.python_features_batched(
            records,
            ip_times,
            static_keywords,
            iter_batches_fn,
            batch_size,
            parallel_enabled,
            parallel_chunk_size,
            max_workers,
        )
    except Exception:
        return None


def supports_chunked_feature_extraction() -> bool:
    if aiwaf_rust is None:
        return False
    return (
        hasattr(aiwaf_rust, "extract_features_batch_with_state")
        and hasattr(aiwaf_rust, "finalize_feature_state")
    )


def extract_features_batch(records, static_keywords, state=None):
    """Chunk-aware feature extraction for Rust backends that support stateful batches.

    Expected extension contract:
    - extract_features_batch_with_state(records, static_keywords, state)
      returns either:
      - {"features": [...], "state": ...}
      - (features, state)
    """
    if aiwaf_rust is None:
        return None, state
    if not hasattr(aiwaf_rust, "extract_features_batch_with_state"):
        return None, state
    try:
        result = aiwaf_rust.extract_features_batch_with_state(records, static_keywords, state)
        if isinstance(result, dict):
            return result.get("features"), result.get("state")
        if isinstance(result, (list, tuple)) and len(result) == 2:
            return result[0], result[1]
        return None, state
    except Exception:
        return None, state


def finalize_feature_state(static_keywords, state=None):
    """Finalize pending state for chunked Rust feature extraction."""
    if aiwaf_rust is None:
        return None
    if not hasattr(aiwaf_rust, "finalize_feature_state"):
        return None
    try:
        result = aiwaf_rust.finalize_feature_state(static_keywords, state)
        if isinstance(result, dict):
            return result.get("features")
        return result
    except Exception:
        return None


def analyze_recent_behavior(entries, static_keywords):
    if aiwaf_rust is None:
        return None
    try:
        return aiwaf_rust.analyze_recent_behavior(entries, static_keywords)
    except Exception:
        return None
