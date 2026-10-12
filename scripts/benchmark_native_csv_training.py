"""Offline real Flask keyword-only training, with state parity checks."""
import argparse
import csv
import json
import logging
from pathlib import Path
import statistics
import sys
import tempfile
import time
from contextlib import redirect_stdout
from io import StringIO

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / 'py'))
from flask import Flask
from aiwaf.flask import trainer, storage
from aiwaf.core.native_runtime import function


def sample(native, count, fmt):
    with tempfile.TemporaryDirectory(prefix='aiwaf-training-') as directory:
        root = Path(directory)
        logs = root / 'logs'
        logs.mkdir()
        with (logs / 'access.log').open('w', newline='', encoding='utf-8') as file:
            writer = csv.writer(file)
            if fmt == 'csv':
                writer.writerow(['timestamp', 'ip', 'method', 'path', 'status_code', 'response_time_ms'])
            for i in range(count):
                ip = f'203.0.113.{i % 20 + 1}'
                path = f'/wp-content/customplugin{i % 5}/shell.php'
                if fmt == 'csv':
                    writer.writerow(['2026-10-10T12:00:00', ip, 'GET', path, '404', '125'])
                else:
                    file.write(f'{ip} - - [10/Oct/2026:12:00:00 +0000] "GET {path} HTTP/1.1" 404 207 "-" "pytest" response-time=0.125\n')
        app = Flask(__name__)
        app.config.update(AIWAF_USE_CSV=True, AIWAF_USE_RUST=True, AIWAF_RUST_CSV=native,
                          AIWAF_DATA_DIR=str(root / 'data'), AIWAF_LOG_DIR=str(logs), AIWAF_EXEMPT_PATHS=[])
        with app.app_context(), redirect_stdout(StringIO()):
            start = time.perf_counter()
            trainer.FlaskAITrainer(app).train(disable_ai=True)
            elapsed = time.perf_counter() - start
            state = (set(storage._read_csv_blacklist()), storage._read_csv_keywords())
            assert len(state[0]) == 20
            assert all(f'customplugin{i}' in state[1] for i in range(5))
            return elapsed, state


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--records', type=int, default=10000)
    parser.add_argument('--runs', type=int, default=3)
    parser.add_argument('--output', type=Path)
    args = parser.parse_args()
    if args.records < 120 or args.runs < 1:
        parser.error('At least 120 records and one run required')
    if not function('training_keywords'):
        parser.error('Build the matching native extension first')
    logging.disable(logging.CRITICAL)
    results = []
    for fmt in ['apache', 'csv']:
        samples = {'python': [], 'rust': []}
        reference = None
        for trial in range(args.runs):
            for mode in (['python', 'rust'] if trial % 2 == 0 else ['rust', 'python']):
                seconds, state = sample(mode == 'rust', args.records, fmt)
                if reference is None:
                    reference = state
                assert state == reference
                samples[mode].append(seconds)
        medians = {mode: statistics.median(values) for mode, values in samples.items()}
        result = dict(format=fmt, median_seconds=medians, python_over_rust=medians['python'] / medians['rust'], samples_seconds=samples)
        results.append(result)
        print(json.dumps(result), flush=True)
    report = dict(records=args.records, runs=args.runs, state_checks_passed=True,
                  scope='Actual Flask keyword-only training including read/parse, aggregation, existing native feature generation, 404 blocks and keyword persistence. Both modes retain the existing Rust feature backend. No AI model fitting or production network.', results=results)
    if args.output:
        args.output.write_text(json.dumps(report, indent=2), encoding='utf-8')


if __name__ == '__main__':
    main()
