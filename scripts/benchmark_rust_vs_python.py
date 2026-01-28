#!/usr/bin/env python3
"""
Quick benchmark: Rust vs Python header validation + CSV logging.
Run from repo root: python scripts/benchmark_rust_vs_python.py
"""

import argparse
import os
import sys
import tempfile
import time
from types import SimpleNamespace

os.environ.setdefault("DJANGO_SETTINGS_MODULE", "tests.test_settings")
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import django

django.setup()

try:
    import aiwaf_rust
except Exception:
    aiwaf_rust = None

from aiwaf.middleware import HeaderValidationMiddleware
from aiwaf.middleware_logger import AIWAFLoggerMiddleware


def python_validate_headers(mw: HeaderValidationMiddleware, headers: dict):
    missing = mw._check_missing_headers(headers)
    if missing:
        return f"Missing required headers: {', '.join(missing)}"
    suspicious_ua = mw._check_user_agent(headers.get("HTTP_USER_AGENT", ""))
    if suspicious_ua:
        return f"Suspicious user agent: {suspicious_ua}"
    suspicious_combo = mw._check_header_combinations(headers)
    if suspicious_combo:
        return f"Suspicious headers: {suspicious_combo}"
    quality_score = mw._calculate_header_quality(headers)
    if quality_score < 3:
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
    args = parser.parse_args()

    headers = {
        "HTTP_USER_AGENT": "Mozilla/5.0 (Windows NT 10.0; Win64; x64)",
        "HTTP_ACCEPT": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
        "HTTP_ACCEPT_LANGUAGE": "en-US,en;q=0.5",
        "HTTP_ACCEPT_ENCODING": "gzip, deflate",
        "HTTP_CONNECTION": "keep-alive",
    }

    mw = HeaderValidationMiddleware(lambda r: None)

    py_time = bench(lambda: python_validate_headers(mw, headers), args.iters)
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

    if aiwaf_rust is not None:
        row_headers, row = logger._build_csv_row(request, response, 0.001)
        rust_csv_time = bench(
            lambda: aiwaf_rust.write_csv_log(csv_path, row_headers, row), args.csv_iters
        )
        print(f"Rust CSV logging:         {args.csv_iters / rust_csv_time:.2f} ops/sec")
    else:
        print("Rust CSV logging:         skipped (aiwaf_rust not available)")

    tmpdir.cleanup()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
