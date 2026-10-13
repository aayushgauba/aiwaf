"""Shared anomaly detection decision engine.

This module centralizes the "AI anomaly" middleware logic so Django/Flask/FastAPI
adapters can share the same scoring, model invocation, and keyword-learning rules.
"""

from __future__ import annotations

from dataclasses import dataclass
import re
import math
from . import rust_backend
from .native_runtime import function as native_function
from typing import Callable, Iterable, List, Optional, Sequence, Set, Tuple, Union, Any

from .constants import STATUS_IDX as DEFAULT_STATUS_IDX
from .rust_backend import analyze_recent_behavior as rust_analyze_recent_behavior
from .rust_backend import is_rust_isolation_forest, rust_available
_DEFAULT_RUST_ANALYZE = rust_analyze_recent_behavior
from .training_logic import is_scanning_path

try:  # optional
    import numpy as np  # type: ignore
    NUMPY_AVAILABLE = True
except Exception:  # pragma: no cover
    np = None
    NUMPY_AVAILABLE = False


HistoryEntry = Tuple[float, str, int, float]  # (timestamp, path, status_code, response_time)


@dataclass(frozen=True)
class AnomalyStats:
    avg_kw_hits: float
    max_404s: int
    avg_burst: float
    total_requests: int
    scanning_404s: int
    legitimate_404s: int
    should_block: bool


@dataclass(frozen=True)
class AnomalyOutcome:
    block: bool
    reason: Optional[str]
    learned_keywords: List[str]
    updated_history: Sequence[HistoryEntry]


def select_native_history(history, model, *, enabled=True):
    """Use native snapshots only for local adapter caches and real Rust models."""
    factory = native_function('NativeAnomalyHistory') if enabled else None
    if factory is None or not is_rust_isolation_forest(model):
        existing_type = getattr(rust_backend.aiwaf_rust, 'NativeAnomalyHistory', None)
        if existing_type is not None and isinstance(history, existing_type):
            return list(history)
        return history
    if isinstance(history, factory):
        return history
    if any(not str(entry[1]).isascii() for entry in (history or [])):
        return history
    try:
        return factory(list(history or []))
    except (TypeError, ValueError, OverflowError):
        return history


def compute_kw_hits(path_lower: str, static_keywords: Sequence[str]) -> int:
    return sum(1 for kw in static_keywords if kw and str(kw) in path_lower)


def trim_history(history: Sequence[HistoryEntry], *, now: float, window_seconds: float) -> List[HistoryEntry]:
    window = max(float(window_seconds), 1.0)
    return [h for h in list(history or []) if now - float(h[0]) < window]


def prune_inactive_histories(cache: dict, *, now: float, window_seconds: float) -> None:
    """Remove only histories with no entries surviving the normal scoring window.

    Local adapters call this periodically while holding their cache lock. Active
    histories are never capped, so burst counts and blocking thresholds stay exact.
    """
    if not math.isfinite(float(now)) or not math.isfinite(float(window_seconds)):
        return
    factory = getattr(rust_backend.aiwaf_rust, 'NativeAnomalyHistory', None)
    window = max(float(window_seconds), 1.0)
    for key, history in list(cache.items()):
        if factory is not None and isinstance(history, factory):
            active = bool(len(history.trimmed(float(now), window)))
        else:
            active = any(now - float(entry[0]) < window for entry in history)
        if not active:
            del cache[key]


def extract_segments(path: str) -> List[str]:
    return [seg for seg in re.split(r"\W+", (path or "").lower()) if len(seg) > 3]


def analyze_recent_behavior_python(
    recent_data: Sequence[HistoryEntry],
    *,
    static_keywords: Sequence[str],
    path_exists: Callable[[str], bool],
    is_exempt_path: Callable[[str], bool],
) -> AnomalyStats:
    recent_kw_hits: List[int] = []
    recent_404s = 0
    recent_burst_counts: List[int] = []
    scanning_404s = 0

    for entry_time, entry_path, entry_status, _entry_resp_time in list(recent_data or []):
        entry_known_path = bool(path_exists(entry_path))
        entry_kw_hits = 0
        if (not entry_known_path) and (not bool(is_exempt_path(entry_path))):
            entry_kw_hits = compute_kw_hits(str(entry_path).lower(), static_keywords)
        recent_kw_hits.append(entry_kw_hits)

        if int(entry_status) == 404:
            recent_404s += 1
            if is_scanning_path(entry_path):
                scanning_404s += 1

        entry_burst = sum(1 for (t, _p, _s, _rt) in recent_data if abs(float(entry_time) - float(t)) <= 10)
        recent_burst_counts.append(entry_burst)

    avg_kw_hits = (sum(recent_kw_hits) / len(recent_kw_hits)) if recent_kw_hits else 0.0
    max_404s = int(recent_404s)
    avg_burst = (sum(recent_burst_counts) / len(recent_burst_counts)) if recent_burst_counts else 0.0
    total_requests = int(len(recent_data or []))
    legitimate_404s = int(max_404s - scanning_404s)

    # Mirrors Django/Flask "enhanced blocking logic".
    should_block = not (
        avg_kw_hits < 3
        and scanning_404s < 5
        and legitimate_404s < 20
        and avg_burst < 25
        and total_requests < 150
    )
    if avg_kw_hits == 0 and max_404s == 0:
        should_block = False

    return AnomalyStats(
        avg_kw_hits=avg_kw_hits,
        max_404s=max_404s,
        avg_burst=avg_burst,
        total_requests=total_requests,
        scanning_404s=int(scanning_404s),
        legitimate_404s=int(legitimate_404s),
        should_block=bool(should_block),
    )


def analyze_recent_behavior(
    recent_data: Sequence[HistoryEntry],
    *,
    static_keywords: Sequence[str],
    path_exists: Callable[[str], bool],
    is_exempt_path: Callable[[str], bool],
    prefer_rust: bool = True,
) -> Optional[AnomalyStats]:
    if not recent_data:
        return None

    stats: Optional[dict] = None
    tuples_native = (native_function('analyze_recent_tuples') if prefer_rust and rust_available()
                     and rust_analyze_recent_behavior is _DEFAULT_RUST_ANALYZE else None)
    if tuples_native is not None:
        try:
            entries = [(str(p).lower(), float(t), int(s),
                        (not bool(path_exists(p))) and (not bool(is_exempt_path(p))))
                       for t, p, s, _rt in recent_data]
            result = tuples_native(entries, list(static_keywords))
            if result is not None:
                return AnomalyStats(*result)
        except Exception:
            pass
    if prefer_rust and rust_available():
        try:
            rust_payload = []
            for entry_time, entry_path, entry_status, _entry_resp_time in list(recent_data):
                entry_known_path = bool(path_exists(entry_path))
                kw_check = (not entry_known_path) and (not bool(is_exempt_path(entry_path)))
                rust_payload.append(
                    {
                        "path_lower": str(entry_path).lower(),
                        "timestamp": float(entry_time),
                        "status": int(entry_status),
                        "kw_check": kw_check,
                    }
                )
            stats = rust_analyze_recent_behavior(rust_payload, list(static_keywords))
        except Exception:
            stats = None

    if stats:
        return AnomalyStats(
            avg_kw_hits=float(stats.get("avg_kw_hits", 0.0)),
            max_404s=int(stats.get("max_404s", 0)),
            avg_burst=float(stats.get("avg_burst", 0.0)),
            total_requests=int(stats.get("total_requests", len(recent_data))),
            scanning_404s=int(stats.get("scanning_404s", 0)),
            legitimate_404s=int(stats.get("legitimate_404s", int(stats.get("max_404s", 0)) - int(stats.get("scanning_404s", 0)))),
            should_block=bool(stats.get("should_block", False)),
        )

    return analyze_recent_behavior_python(
        recent_data,
        static_keywords=static_keywords,
        path_exists=path_exists,
        is_exempt_path=is_exempt_path,
    )


def predict_anomaly(model: Any, features: Sequence[Union[int, float]]) -> Optional[int]:
    if model is None:
        return None
    try:
        if is_rust_isolation_forest(model):
            pred = model.predict([list(map(float, features))])[0]
            return int(pred)
        if not NUMPY_AVAILABLE:
            return None
        X = np.array(list(features), dtype=float).reshape(1, -1)  # type: ignore[attr-defined]
        pred = model.predict(X)[0]
        return int(pred)
    except Exception:
        return None


def build_feature_vector(
    *,
    path: str,
    status_code: int,
    response_time: float,
    now: float,
    history: Sequence[HistoryEntry],
    static_keywords: Sequence[str],
    status_index_values: Sequence[str] = DEFAULT_STATUS_IDX,
    path_exists_current: bool,
    is_exempt_path_current: bool,
) -> List[float]:
    path_len = len(path or "")
    kw_hits = 0
    if (not path_exists_current) and (not is_exempt_path_current):
        kw_hits = compute_kw_hits((path or "").lower(), static_keywords)

    status_code_str = str(int(status_code))
    status_idx = status_index_values.index(status_code_str) if status_code_str in status_index_values else -1
    burst_count = sum(1 for (t, _p, _s, _rt) in history if now - float(t) <= 10)
    total_404 = sum(1 for (_t, _p, s, _rt) in history if int(s) == 404)
    return [float(path_len), float(kw_hits), float(response_time), float(status_idx), float(burst_count), float(total_404)]


def evaluate_anomaly(
    *,
    ip: str,
    path: str,
    status_code: int,
    response_time: float,
    now: float,
    history: Sequence[HistoryEntry],
    window_seconds: float,
    model: Any,
    static_keywords: Sequence[str],
    malicious_keywords: Sequence[str],
    keyword_learning_enabled: bool,
    path_exists: Callable[[str], bool],
    is_exempt_path: Callable[[str], bool],
    is_malicious_context: Callable[[str], bool],
    status_index_values: Sequence[str] = DEFAULT_STATUS_IDX,
    legitimate_keywords: Optional[Set[str]] = None,
) -> AnomalyOutcome:
    legitimate_keywords = legitimate_keywords or set()

    # Update + trim history first (so burst/404 counts include recent window).
    factory = native_function('NativeAnomalyHistory')
    native_history = (factory is not None and isinstance(history, factory)
        and is_rust_isolation_forest(model) and str(path).isascii()
        and all(isinstance(kw, str) and kw.isascii() for kw in (*static_keywords, *malicious_keywords))
        and all(math.isfinite(float(v)) for v in (now, window_seconds, response_time))
        and history.supports_ascii())
    trimmed = (history.trimmed(float(now), float(window_seconds)) if native_history else
               trim_history(history, now=now, window_seconds=window_seconds))
    path_exists_current = bool(path_exists(path))
    exempt_current = bool(is_exempt_path(path))

    if not native_history:
        feats = build_feature_vector(
            path=path,
            status_code=status_code,
            response_time=response_time,
            now=now,
            history=trimmed,
            static_keywords=static_keywords,
            status_index_values=status_index_values,
            path_exists_current=path_exists_current,
            is_exempt_path_current=exempt_current,
        )

    block = False
    reason = None

    if native_history:
        try:
            prediction, _features = trimmed.predict_current(model, str(path), int(status_code),
                float(response_time), float(now), not path_exists_current and not exempt_current,
                list(static_keywords), list(status_index_values))
        except Exception:
            feats = build_feature_vector(path=path, status_code=status_code, response_time=response_time,
                now=now, history=list(trimmed), static_keywords=static_keywords,
                status_index_values=status_index_values, path_exists_current=path_exists_current,
                is_exempt_path_current=exempt_current)
            prediction = predict_anomaly(model, feats)
    else:
        prediction = predict_anomaly(model, feats)
    if prediction == -1:
        if native_history:
            try:
                paths = trimmed.recent_paths(float(now))
                checks = [(not bool(path_exists(p))) and (not bool(is_exempt_path(p))) for p in paths]
                native_stats = trimmed.analyze(float(now), list(malicious_keywords), checks)
                stats = AnomalyStats(*native_stats) if native_stats is not None else None
            except Exception:
                recent_data = [d for d in trimmed if now - float(d[0]) <= 300]
                stats = analyze_recent_behavior(recent_data, static_keywords=malicious_keywords,
                    path_exists=path_exists, is_exempt_path=is_exempt_path, prefer_rust=True)
        else:
            recent_data = [d for d in trimmed if now - float(d[0]) <= 300]
            stats = analyze_recent_behavior(
                recent_data,
                static_keywords=malicious_keywords,
                path_exists=path_exists,
                is_exempt_path=is_exempt_path,
                prefer_rust=True,
            )
        if stats and stats.should_block:
            reason = (
                "AI anomaly + scanning behavior "
                f"(404s:{stats.max_404s}, scanning:{stats.scanning_404s}, "
                f"kw:{stats.avg_kw_hits:.1f}, burst:{stats.avg_burst:.1f})"
            )
            block = True
    elif prediction is not None:
        # Conservative fallback: require both scanning path + enough keyword hits.
        current_scanning = is_scanning_path(path)
        current_kw_hits = compute_kw_hits((path or "").lower(), malicious_keywords)
        if current_kw_hits >= 3 and current_scanning:
            reason = f"AI anomaly + scanning behavior (kw:{current_kw_hits}, scanning_path:{path})"
            block = True

    if native_history:
        updated = trimmed.appended(float(now), str(path), int(status_code), float(response_time))
    else:
        updated = list(trimmed)
        updated.append((float(now), str(path), int(status_code), float(response_time)))
        updated = trim_history(updated, now=now, window_seconds=window_seconds)

    learned_keywords: List[str] = []
    if (
        keyword_learning_enabled
        and int(status_code) == 404
        and (not path_exists_current)
        and (not exempt_current)
    ):
        for seg in extract_segments(path):
            if seg in set(static_keywords):
                continue
            if seg in legitimate_keywords:
                continue
            if seg in set(malicious_keywords):
                continue
            if is_malicious_context(seg):
                learned_keywords.append(seg)

    return AnomalyOutcome(block=block, reason=reason, learned_keywords=learned_keywords, updated_history=updated)

