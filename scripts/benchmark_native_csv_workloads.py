"""Offline Flask workload timings with response and persisted-state checks."""
import argparse
import csv
import json
import logging
from pathlib import Path
import statistics
import sys
import tempfile
import time

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / 'py'))
from flask import Flask
from aiwaf.core import native_runtime, storage_csv_impl
from aiwaf.flask.ip_and_keyword_block_middleware import IPAndKeywordBlockMiddleware
from aiwaf.flask.logging_middleware import AIWAFLoggingMiddleware


def sample(scenario, native, requests, rows):
    # Each trial starts from identical data; fresh blocks use a different IP.
    with tempfile.TemporaryDirectory(prefix='aiwaf-workload-') as directory:
        root = Path(directory)
        data = root / 'data'
        app = Flask(__name__)
        app.config.update(AIWAF_USE_CSV=True, AIWAF_USE_RUST=True,
            AIWAF_RUST_CSV=native, AIWAF_DATA_DIR=str(data), AIWAF_EXEMPT_PATHS=[],
            AIWAF_LOG_DIR=str(root / 'logs'), AIWAF_LOG_FORMAT='csv')
        app.add_url_rule('/docs', 'docs', lambda: 'ok')
        with app.app_context():
            storage_csv_impl.ensure_all(data)
            storage_csv_impl.rewrite_blacklist(data, {
                f'198.18.{i // 256}.{i % 256}': {'reason': 'synthetic', 'permanent': True}
                for i in range(rows)})
        if scenario == 'csv_logging':
            app.aiwaf_logger = AIWAFLoggingMiddleware(app)
        IPAndKeywordBlockMiddleware(app)
        client = app.test_client()
        assert client.get('/docs').status_code == 200
        start = time.perf_counter()
        for i in range(requests):
            path = '/wp-content/plugins/pods/init.php' if scenario == 'fresh_blocks' else '/docs'
            response = client.get(path, environ_base={'REMOTE_ADDR': f'203.0.113.{i + 1}'})
            assert response.status_code == (403 if scenario == 'fresh_blocks' else 200)
        elapsed = time.perf_counter() - start
        with app.app_context():
            persisted = len(storage_csv_impl.read_blacklist(data))
        assert persisted == rows + (requests if scenario == 'fresh_blocks' else 0)
        if scenario == 'csv_logging':
            with (root / 'logs' / 'access.log').open(newline='', encoding='utf-8') as file:
                assert len(list(csv.DictReader(file))) == requests + 1
            app.aiwaf_logger.close()
        return elapsed * 1000 / requests


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--requests', type=int, default=20)
    parser.add_argument('--rows', type=int, default=100)
    parser.add_argument('--runs', type=int, default=3)
    parser.add_argument('--output', type=Path)
    args = parser.parse_args()
    if args.requests < 1 or args.requests > 250 or args.runs < 1 or not 0 <= args.rows <= 65536:
        parser.error('requests=1..250, rows=0..65536 and runs>=1 required')
    if native_runtime.csv_function('csv_keyword_apply') is None:
        parser.error('Build/install the matching native CSV extension first')
    logging.disable(logging.CRITICAL)
    results = []
    for scenario in ['allowed', 'fresh_blocks', 'csv_logging']:
        samples = {'python': [], 'rust': []}
        for trial in range(args.runs):
            for mode in (['python', 'rust'] if trial % 2 == 0 else ['rust', 'python']):
                samples[mode].append(sample(scenario, mode == 'rust', args.requests, args.rows))
        medians = {mode: statistics.median(values) for mode, values in samples.items()}
        result = {'scenario': scenario, 'median_ms_per_request': medians,
            'python_over_rust': medians['python'] / medians['rust'], 'samples_ms': samples}
        results.append(result)
        print(json.dumps(result), flush=True)
    report = {'scope': 'Offline Flask test client plus IP/keyword middleware; csv_logging also enables logging. No network, full middleware chain, or concurrent requests.',
        'requests_per_run': args.requests, 'runs': args.runs, 'initial_blacklist_rows': args.rows,
        'state_and_status_checks_passed': True, 'results': results}
    if args.output:
        args.output.write_text(json.dumps(report, indent=2), encoding='utf-8')


if __name__ == '__main__':
    main()
