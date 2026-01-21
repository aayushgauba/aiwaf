#!/usr/bin/env python3
"""
Stress test CSV logging with multiple processes writing concurrently.
Run manually (not part of the unit test suite).
"""

import os
import sys
import csv
import argparse
import multiprocessing as mp

# Setup Django
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
os.environ.setdefault("DJANGO_SETTINGS_MODULE", "tests.test_settings")

import django
django.setup()

from django.http import HttpResponse
from django.test import override_settings
from django.test.client import RequestFactory


def _worker(log_path, count):
    from aiwaf.middleware_logger import AIWAFLoggerMiddleware

    with override_settings(
        AIWAF_MIDDLEWARE_LOGGING=True,
        AIWAF_MIDDLEWARE_LOG=log_path,
        AIWAF_MIDDLEWARE_CSV=True,
        AIWAF_MIDDLEWARE_DB=False,
    ):
        middleware = AIWAFLoggerMiddleware(lambda request: HttpResponse(status=200))
        factory = RequestFactory()
        for _ in range(count):
            request = factory.get(
                "/api/ping/",
                HTTP_USER_AGENT="StressTest/1.0",
                HTTP_ACCEPT="*/*",
            )
            middleware.process_request(request)
            middleware.process_response(request, HttpResponse(status=200))


def main():
    parser = argparse.ArgumentParser(description="Stress test CSV logging.")
    parser.add_argument("--processes", type=int, default=4, help="Number of worker processes.")
    parser.add_argument("--requests", type=int, default=100, help="Requests per process.")
    parser.add_argument("--log-path", default="aiwaf_requests.log", help="Base log file path.")
    parser.add_argument("--fresh", action="store_true", help="Remove existing CSV/log lock before running.")
    args = parser.parse_args()

    csv_path = args.log_path.replace(".log", ".csv")
    lock_path = csv_path + ".lock"
    if args.fresh:
        for path in (csv_path, lock_path):
            if os.path.exists(path):
                os.remove(path)

    processes = []
    for _ in range(args.processes):
        p = mp.Process(target=_worker, args=(args.log_path, args.requests))
        p.start()
        processes.append(p)
    for p in processes:
        p.join()

    if not os.path.exists(csv_path):
        print("CSV log file was not created:", csv_path)
        return 1

    with open(csv_path, "r", encoding="utf-8", newline="") as f:
        rows = list(csv.DictReader(f))

    expected = args.processes * args.requests
    actual = len(rows)
    print(f"CSV rows: {actual} (expected ~{expected})")
    if actual < expected:
        print("Warning: fewer rows than expected (possible concurrent write loss).")
        return 2
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
