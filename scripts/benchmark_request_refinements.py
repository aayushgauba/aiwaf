"""Measure immediate logging, Flask adapter reuse, and recent burst analysis."""
import argparse
import csv
import json
from pathlib import Path
import statistics
import tempfile
import time


def measure(call, count, runs):
    samples = []
    for _ in range(runs):
        start = time.perf_counter()
        for _ in range(count):
            call()
        samples.append((time.perf_counter() - start) / count)
    return statistics.median(samples)


def previous_route_exists(path):
    # Previous middleware implementation, with its exception import corrected
    # so both benchmark paths perform a real routing lookup.
    try:
        from flask import current_app
        from werkzeug.routing import RequestRedirect
        from werkzeug.exceptions import MethodNotAllowed
        adapter = current_app.url_map.bind('localhost')
        try:
            adapter.match(path)
            return True
        except (RequestRedirect, MethodNotAllowed):
            return True
        except Exception:
            return False
    except Exception:
        return False


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--requests', type=int, default=300)
    parser.add_argument('--runs', type=int, default=5)
    parser.add_argument('--burst-only', action='store_true')
    parser.add_argument('--output', type=Path)
    args = parser.parse_args()
    if args.requests < 1 or args.runs < 1:
        parser.error('Positive counts required')
    import aiwaf_rust
    result = {'requests': args.requests, 'runs': args.runs, 'burst_seconds': {}}
    for count in (20, 200, 1000):
        entries = [('/docs', ((i * 7919) % 1031) / 10., 404, True) for i in range(count)]
        times = [row[1] for row in entries]
        stats = aiwaf_rust.analyze_recent_tuples(entries, [])
        expected = sum(sum(t - 10. <= other <= t + 10. for other in times) for t in times) / count
        assert stats[2] == expected
        result['burst_seconds'][count] = measure(lambda: aiwaf_rust.analyze_recent_tuples(entries, []), args.requests, args.runs)
    if not args.burst_only:
        from aiwaf.core.logs import write_csv_log
        from aiwaf.core.native_runtime import native_override, close_csv_logs
        from flask import Flask
        from aiwaf.flask.anomaly_middleware import AIAnomalyMiddleware
        result['logging_seconds'] = {}
        headers = ['timestamp', 'ip', 'method', 'path', 'status_code', 'response_time_ms', 'user_agent']
        row = dict(zip(headers, ['2026-10-12', '203.0.113.1', 'GET', '/docs', 200, 10, 'benchmark']))
        with tempfile.TemporaryDirectory(prefix='aiwaf-refinements-') as directory:
            for enabled in (False, True):
                path = str(Path(directory) / f'{enabled}.csv')
                with native_override(enabled):
                    write_csv_log(path, headers, row)
                    result['logging_seconds']['native' if enabled else 'python'] = measure(
                        lambda: write_csv_log(path, headers, row), args.requests, args.runs)
                close_csv_logs(path)
                with open(path, newline='', encoding='utf-8') as stream:
                    rows = list(csv.reader(stream))
                assert rows[0] == headers and len(rows) == 2 + args.requests * args.runs
                assert all(record == [str(row[key]) for key in headers] for record in rows[1:])
        app = Flask(__name__)
        app.add_url_rule('/items/<int:item>', view_func=lambda item: str(item))
        middleware = AIAnomalyMiddleware()
        with app.test_request_context('/items/42'):
            assert middleware._route_exists('/items/42')
            result['route_seconds'] = {
                'previous': measure(lambda: previous_route_exists('/items/42'), args.requests, args.runs),
                'reused': measure(lambda: middleware._route_exists('/items/42'), args.requests, args.runs),
            }
    result['scope'] = 'Isolated immediate CSV writes, repeated route lookups within one request, and Rust recent analysis including tuple conversion. No HTTP server or concurrent load.'
    serialized = json.dumps(result, indent=2)
    print(serialized)
    if args.output:
        args.output.write_text(serialized, encoding='utf-8')


if __name__ == '__main__':
    main()
