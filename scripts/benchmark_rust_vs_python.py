#!/usr/bin/env python3
"""
Quick benchmark: Rust vs Python header validation + CSV logging.
Run from repo root: python scripts/benchmark_rust_vs_python.py
"""

import argparse
import csv
import os
import random
import sys
import tempfile
import time
from collections import defaultdict
from datetime import datetime, timedelta
from types import SimpleNamespace

os.environ.setdefault("DJANGO_SETTINGS_MODULE", "tests.test_settings")
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import django

django.setup()

try:
    import aiwaf_rust
except Exception:
    aiwaf_rust = None

import aiwaf.middleware as middleware_module
from aiwaf.middleware import HeaderValidationMiddleware, AIAnomalyMiddleware
from aiwaf.middleware_logger import AIWAFLoggerMiddleware
from aiwaf import trainer as trainer_module
from django.conf import settings


def python_validate_headers(
    mw: HeaderValidationMiddleware,
    headers: dict,
    required_headers,
    min_score: int,
):
    missing = mw._check_missing_headers(headers, required_headers)
    if missing:
        return f"Missing required headers: {', '.join(missing)}"
    suspicious_ua = mw._check_user_agent(headers.get("HTTP_USER_AGENT", ""))
    if suspicious_ua:
        return f"Suspicious user agent: {suspicious_ua}"
    suspicious_combo = mw._check_header_combinations(headers, required_headers)
    if suspicious_combo:
        return f"Suspicious headers: {suspicious_combo}"
    quality_score = mw._calculate_header_quality(headers)
    if quality_score < min_score:
        return f"Low header quality score: {quality_score}"
    return None


def bench(fn, iterations: int) -> float:
    start = time.perf_counter()
    for _ in range(iterations):
        fn()
    end = time.perf_counter()
    return end - start


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--iters", type=int, default=10000)
    parser.add_argument("--csv-iters", type=int, default=1000)
    parser.add_argument("--feature-size", type=int, default=200000, help="Synthetic records for feature benchmark")
    parser.add_argument("--feature-iters", type=int, default=20, help="Iterations for feature benchmark")
    parser.add_argument("--anomaly-size", type=int, default=500, help="Recent entries for anomaly benchmark")
    parser.add_argument("--anomaly-iters", type=int, default=2000, help="Iterations for anomaly benchmark")
    args = parser.parse_args()

    headers = {
        "HTTP_USER_AGENT": "Mozilla/5.0 (Windows NT 10.0; Win64; x64)",
        "HTTP_ACCEPT": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
        "HTTP_ACCEPT_LANGUAGE": "en-US,en;q=0.5",
        "HTTP_ACCEPT_ENCODING": "gzip, deflate",
        "HTTP_CONNECTION": "keep-alive",
    }

    mw = HeaderValidationMiddleware(lambda r: None)
    bench_request = SimpleNamespace(method="GET", path="/bench")
    required_headers = mw._get_required_headers(bench_request)
    min_score = mw._get_min_quality_score(required_headers)

    tmp_access_log = tempfile.NamedTemporaryFile(delete=False, suffix=".csv")
    tmp_access_log_path = tmp_access_log.name
    tmp_access_log.close()

    def write_temp_access_log(path: str, rows: int):
        fieldnames = [
            "timestamp",
            "ip",
            "method",
            "path",
            "status_code",
            "content_length",
            "referer",
            "user_agent",
            "response_time",
        ]
        with open(path, "w", newline="", encoding="utf-8") as f:
            writer = csv.DictWriter(f, fieldnames=fieldnames)
            writer.writeheader()
            base = datetime.now()
            for i in range(rows):
                writer.writerow({
                    "timestamp": (base - timedelta(seconds=i)).isoformat(),
                    "ip": f"192.0.2.{i % 250}",
                    "method": "GET",
                    "path": "/benchmark",
                    "status_code": 200,
                    "content_length": 1234,
                    "referer": "-",
                    "user_agent": headers["HTTP_USER_AGENT"],
                    "response_time": 0.123,
                })

    write_temp_access_log(tmp_access_log_path, max(10000, args.feature_size // 2))

    original_access_log = getattr(settings, "AIWAF_ACCESS_LOG", None)
    original_min_logs = getattr(settings, "AIWAF_MIN_AI_LOGS", 10000)
    settings.AIWAF_ACCESS_LOG = tmp_access_log_path
    settings.AIWAF_MIN_AI_LOGS = min(original_min_logs, max(1000, args.feature_size // 2))

    py_time = bench(
        lambda: python_validate_headers(mw, headers, required_headers, min_score),
        args.iters,
    )
    print(f"Python header validation: {args.iters / py_time:.2f} ops/sec")

    if aiwaf_rust is not None:
        rust_time = bench(lambda: aiwaf_rust.validate_headers(headers), args.iters)
        print(f"Rust header validation:   {args.iters / rust_time:.2f} ops/sec")
    else:
        print("Rust header validation:   skipped (aiwaf_rust not available)")

    # CSV logging benchmark
    tmpdir = tempfile.TemporaryDirectory()
    csv_path = os.path.join(tmpdir.name, "bench.csv")
    logger = AIWAFLoggerMiddleware(lambda r: None)
    logger.log_file = csv_path

    request = SimpleNamespace(
        method="GET",
        path="/bench",
        META={
            "HTTP_USER_AGENT": headers["HTTP_USER_AGENT"],
            "HTTP_REFERER": "",
        },
    )
    response = SimpleNamespace(status_code=200, get=lambda k, d="-": d)

    py_csv_time = bench(lambda: logger._write_csv_log(request, response, 0.001), args.csv_iters)
    print(f"Python CSV logging:       {args.csv_iters / py_csv_time:.2f} ops/sec")

    print("Rust CSV logging:         not applicable (Python-only)")

    # Feature extraction benchmark (trainer: Python vs Rust)
    def build_feature_inputs(count: int, unique_ips: int):
        base = datetime.now()
        parsed = []
        ip_404 = defaultdict(int)
        ip_times = defaultdict(list)
        sample_paths = [
            "/login",
            "/admin/",
            "/.env",
            "/wp-admin/install.php",
            "/api/v1/users",
            "/search?q=admin",
        ]
        status_choices = ["200", "404", "403"]
        for i in range(count):
            ip = f"198.51.100.{i % max(unique_ips, 1)}"
            path = random.choice(sample_paths)
            status = random.choice(status_choices)
            ts = base + timedelta(seconds=(i % 120))
            resp_time = 0.05 + (i % 40) * 0.01
            parsed.append({
                "ip": ip,
                "timestamp": ts,
                "path": path,
                "status": status,
                "response_time": resp_time,
            })
            ip_times[ip].append(ts)
            if status == "404":
                ip_404[ip] += 1
        return parsed, ip_404, ip_times

    parsed, ip_404, ip_times = build_feature_inputs(args.feature_size, args.feature_size // 10)

    orig_path_exists = trainer_module.path_exists_in_django
    orig_is_exempt = trainer_module.is_exempt_path
    trainer_module.path_exists_in_django = lambda path: False
    trainer_module.is_exempt_path = lambda path: False

    def bench_features(use_rust: bool):
        prev_setting = getattr(settings, "AIWAF_USE_RUST", False)
        settings.AIWAF_USE_RUST = use_rust
        try:
            return bench(lambda: trainer_module._generate_feature_dicts(parsed, ip_404, ip_times), args.feature_iters)
        finally:
            settings.AIWAF_USE_RUST = prev_setting

    try:
        try:
            py_feat_time = bench_features(False)
            print(f"Python feature extraction: {args.feature_iters / py_feat_time:.2f} batches/sec")

            if aiwaf_rust is not None:
                rust_feat_time = bench_features(True)
                print(f"Rust feature extraction:   {args.feature_iters / rust_feat_time:.2f} batches/sec")
            else:
                print("Rust feature extraction:   skipped (aiwaf_rust not available)")
        finally:
            trainer_module.path_exists_in_django = orig_path_exists
            trainer_module.is_exempt_path = orig_is_exempt

        # Anomaly analysis benchmark
        def build_recent_entries(count: int):
            now = time.time()
            entries = []
            sample_paths = [
                "/wp-admin/install.php",
                "/api/data",
                "/search",
                "/adminer.php",
                "/status",
                "/.env",
            ]
            status_choices = [200, 403, 404]
            for i in range(count):
                path = random.choice(sample_paths)
                status = random.choice(status_choices)
                ts = now - (i % 300)
                entries.append((ts, path, status, 0.1))
            return entries

        recent_entries = build_recent_entries(args.anomaly_size)
        anomaly_mw = AIAnomalyMiddleware(lambda r: None)
        orig_mw_path_exists = middleware_module.path_exists_in_django
        orig_mw_is_exempt = middleware_module.is_exempt_path
        middleware_module.path_exists_in_django = lambda path: False
        middleware_module.is_exempt_path = lambda path: False

        def bench_anomaly(use_rust: bool):
            prev_setting = getattr(settings, "AIWAF_USE_RUST", False)
            settings.AIWAF_USE_RUST = use_rust
            try:
                return bench(lambda: anomaly_mw._analyze_recent_behavior(recent_entries), args.anomaly_iters)
            finally:
                settings.AIWAF_USE_RUST = prev_setting

        try:
            py_anomaly_time = bench_anomaly(False)
            print(f"Python anomaly analysis:   {args.anomaly_iters / py_anomaly_time:.2f} batches/sec")

            if aiwaf_rust is not None:
                rust_anomaly_time = bench_anomaly(True)
                print(f"Rust anomaly analysis:     {args.anomaly_iters / rust_anomaly_time:.2f} batches/sec")
            else:
                print("Rust anomaly analysis:     skipped (aiwaf_rust not available)")
        finally:
            middleware_module.path_exists_in_django = orig_mw_path_exists
            middleware_module.is_exempt_path = orig_mw_is_exempt
    finally:
        tmpdir.cleanup()
        try:
            os.unlink(tmp_access_log_path)
        except OSError:
            pass
        settings.AIWAF_ACCESS_LOG = original_access_log
        settings.AIWAF_MIN_AI_LOGS = original_min_logs
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
