"""Compare the CSV-backed Flask IP/keyword request path; never contacts a site."""
import argparse
import json
from pathlib import Path
import statistics
import sys
import tempfile
import time

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / 'py'))
from flask import Flask
from aiwaf.core import rust_backend, storage_csv_impl
from aiwaf.flask.ip_and_keyword_block_middleware import IPAndKeywordBlockMiddleware


def run(rows, requests, repetitions):
    with tempfile.TemporaryDirectory(prefix='aiwaf-native-csv-') as directory:
        data = Path(directory)
        storage_csv_impl.ensure_all(data)
        storage_csv_impl.rewrite_blacklist(data, {
            f'198.18.{i // 256}.{i % 256}': {'reason': 'synthetic', 'permanent': True}
            for i in range(rows)
        })
        samples = {'python': [], 'rust': []}
        app = Flask(__name__)
        app.config.update(AIWAF_USE_CSV=True, AIWAF_USE_RUST=True,
                          AIWAF_EXEMPT_PATHS=[], AIWAF_DATA_DIR=directory)
        IPAndKeywordBlockMiddleware(app)
        app.add_url_rule('/docs', 'docs', lambda: 'ok')
        client = app.test_client()
        for trial in range(repetitions):
            for mode in (['python', 'rust'] if trial % 2 == 0 else ['rust', 'python']):
                app.config['AIWAF_RUST_CSV'] = mode == 'rust'
                # Warm template-independent request machinery and the native snapshot/index.
                assert client.get('/docs', environ_base={'REMOTE_ADDR': '213.35.106.249'}).status_code == 200
                start = time.perf_counter()
                for _ in range(requests):
                    assert client.get('/docs', environ_base={'REMOTE_ADDR': '213.35.106.249'}).status_code == 200
                samples[mode].append((time.perf_counter() - start) / requests)
        medians = {mode: statistics.median(values) for mode, values in samples.items()}
        return {'blacklist_rows': rows, 'requests_per_run': requests, 'runs': repetitions,
                'median_ms_per_request': {mode: seconds * 1000 for mode, seconds in medians.items()},
                'speedup': medians['python'] / medians['rust'], 'samples_seconds_per_request': samples}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--rows', nargs='+', type=int, default=[100, 1000, 10000])
    parser.add_argument('--requests', type=int, default=30)
    parser.add_argument('--runs', type=int, default=3)
    parser.add_argument('--output', type=Path)
    args = parser.parse_args()
    if not all(hasattr(rust_backend.aiwaf_rust, capability) for capability in ('csv_blacklist_check', 'policy_keyword')):
        parser.error('Build/install the new Rust extension before benchmarking')
    results = []
    for rows in args.rows:
        result = run(rows, args.requests, args.runs)
        results.append(result)
        print(json.dumps(result), flush=True)
    if args.output:
        args.output.write_text(json.dumps({'scope': 'Flask test-client, IP/keyword middleware only, warm cache, no network or contention', 'results': results}, indent=2))


if __name__ == '__main__':
    main()
