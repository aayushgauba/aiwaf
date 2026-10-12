"""Offline request with eight exemption checks, native CSV on in both modes."""
import argparse
import json
from pathlib import Path
import statistics
import sys
import tempfile
import time
sys.path.insert(0, str(Path(__file__).resolve().parents[1] / 'py'))
from flask import Flask, request
from aiwaf.flask import utils
from aiwaf.core import storage_csv_impl


def sample(reuse, count):
    with tempfile.TemporaryDirectory(prefix='aiwaf-reuse-') as directory:
        app = Flask(__name__)
        app.config.update(AIWAF_DATA_DIR=directory, AIWAF_USE_RUST=True, AIWAF_USE_CSV=True,
                          AIWAF_RUST_CSV=True, AIWAF_CSV_REQUEST_CACHE=reuse, AIWAF_EXEMPT_PATHS=[])
        with app.app_context():
            storage_csv_impl.ensure_all(Path(directory))
        def check():
            assert not utils.is_exempt(request)
        for i in range(8):
            app.before_request(check)
        app.add_url_rule('/docs', 'docs', lambda: 'ok')
        client = app.test_client()
        assert client.get('/docs').status_code == 200
        start = time.perf_counter()
        for i in range(count):
            assert client.get('/docs').status_code == 200
        return (time.perf_counter() - start) * 1000 / count


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--requests', type=int, default=100)
    parser.add_argument('--runs', type=int, default=3)
    parser.add_argument('--output', type=Path)
    args = parser.parse_args()
    if args.requests < 1 or args.runs < 1:
        parser.error('Positive request/run counts required')
    if utils.csv_function('csv_request_exempt') is None:
        parser.error('Matching native extension required')
    samples = {'original': [], 'reuse': []}
    for trial in range(args.runs):
        for mode in (['original', 'reuse'] if trial % 2 == 0 else ['reuse', 'original']):
            samples[mode].append(sample(mode == 'reuse', args.requests))
    medians = {mode: statistics.median(values) for mode, values in samples.items()}
    report = dict(scope=__doc__, runs=args.runs, requests=args.requests,
                  median_ms_per_request=medians, original_over_reuse=medians['original'] / medians['reuse'],
                  samples_ms=samples, status_checks_passed=True)
    print(json.dumps(report), flush=True)
    if args.output:
        args.output.write_text(json.dumps(report, indent=2), encoding='utf-8')


if __name__ == '__main__':
    main()
