"""
Shared feature extraction helpers for training.
"""

from __future__ import annotations

from concurrent.futures import ThreadPoolExecutor

from . import rust_backend
from .native_runtime import function


def extract_native_batch(parsed, ip_404, exists, exempt, statuses, keywords):
    native = function('extract_native_training_features')
    if native is None:
        return None
    eligible = {path: not exists(path) and not exempt(path)
                for path in dict.fromkeys(record['path'] for record in parsed)}
    return native(parsed, eligible, dict(ip_404), list(statuses), list(keywords))


def extract_raw_features(parsed, ip_404, path_exists_fn, path_exempt_fn, status_idx_list, static_kw):
    """Prepare only unique path eligibility, then let Rust build and score the batch."""
    if not parsed or not rust_backend.supports_raw_feature_extraction():
        return None
    eligible_paths = {}
    for record in parsed:
        path = record["path"]
        if path in eligible_paths:
            continue
        try:
            known_path = bool(path_exists_fn(path))
        except Exception:
            known_path = False
        try:
            exempt_path = bool(path_exempt_fn(path))
        except Exception:
            exempt_path = False
        eligible_paths[path] = not known_path and not exempt_path
    return rust_backend.extract_raw_features(parsed, eligible_paths, ip_404, status_idx_list, static_kw)


def build_records(parsed, ip_404, path_exists_fn, path_exempt_fn, status_idx_list):
    rust_records = rust_backend.build_records(parsed, ip_404, path_exists_fn, path_exempt_fn, status_idx_list)
    if rust_records is not None:
        return rust_records

    records = []
    known_cache = {}
    exempt_cache = {}
    for record in parsed:
        path = record["path"]
        known_path = known_cache.get(path)
        if known_path is None:
            try:
                known_path = path_exists_fn(path)
            except Exception:
                known_path = False
            known_cache[path] = known_path

        exempt = exempt_cache.get(path)
        if exempt is None:
            try:
                exempt = path_exempt_fn(path)
            except Exception:
                exempt = False
            exempt_cache[path] = exempt

        kw_check = (not known_path) and (not exempt)
        status_idx = status_idx_list.index(record["status"]) if record["status"] in status_idx_list else -1
        records.append({
            "ip": record["ip"],
            "path_len": len(path),
            "path_lower": path.lower(),
            "resp_time": record["response_time"],
            "status_idx": status_idx,
            "timestamp": record["timestamp"],
            "timestamp_epoch": record["timestamp"].timestamp(),
            "kw_check": kw_check,
            "total_404": ip_404.get(record["ip"], 0),
        })
    return records


def rust_payload_from_records(records):
    rust_payload = rust_backend.rust_payload_from_records(records)
    if rust_payload is not None:
        return rust_payload

    return [
        {
            "ip": rec["ip"],
            "path_lower": rec["path_lower"],
            "path_len": rec["path_len"],
            "timestamp": rec["timestamp_epoch"],
            "response_time": rec["resp_time"],
            "status_idx": rec["status_idx"],
            "kw_check": rec["kw_check"],
            "total_404": rec["total_404"],
        }
        for rec in records
    ]


def python_feature_from_record(rec, ip_times, static_kw):
    rust_feature = rust_backend.python_feature_from_record(rec, ip_times, static_kw)
    if rust_feature is not None:
        return rust_feature

    kw_hits = 0
    if rec["kw_check"]:
        path_lower = rec["path_lower"]
        kw_hits = sum(1 for kw in static_kw if kw in path_lower)

    burst = 0
    timestamps = ip_times.get(rec["ip"], [])
    for ts in timestamps:
        if (rec["timestamp"] - ts).total_seconds() <= 10:
            burst += 1

    return {
        "ip": rec["ip"],
        "path_len": rec["path_len"],
        "kw_hits": kw_hits,
        "resp_time": rec["resp_time"],
        "status_idx": rec["status_idx"],
        "burst_count": burst,
        "total_404": rec["total_404"],
    }


def python_features_batched(records, ip_times, static_kw, iter_batches_fn, batch_size: int, parallel_enabled: bool, parallel_chunk_size: int, max_workers: int):
    rust_features = rust_backend.python_features_batched(
        records,
        ip_times,
        static_kw,
        iter_batches_fn,
        batch_size,
        parallel_enabled,
        parallel_chunk_size,
        max_workers,
    )
    if rust_features is not None:
        return rust_features

    if not records:
        return []

    batch_size = max(1, int(batch_size))
    parallel_chunk_size = max(1, int(parallel_chunk_size))
    max_workers = max(1, int(max_workers))

    features = []
    if parallel_enabled and max_workers > 1:
        with ThreadPoolExecutor(max_workers=max_workers) as executor:
            for batch in iter_batches_fn(records, batch_size):
                if len(batch) >= parallel_chunk_size:
                    features.extend(list(executor.map(lambda r: python_feature_from_record(r, ip_times, static_kw), batch)))
                else:
                    features.extend([python_feature_from_record(r, ip_times, static_kw) for r in batch])
        return features

    for batch in iter_batches_fn(records, batch_size):
        features.extend([python_feature_from_record(r, ip_times, static_kw) for r in batch])
    return features
