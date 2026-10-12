"""Profile the synchronous native CSV writer; no website/network requests."""
import argparse
import csv
import json
from pathlib import Path
import statistics
import tempfile
import time
import aiwaf_rust

def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--rows', type=int, default=100)
    parser.add_argument('--output', type=Path)
    args = parser.parse_args()
    if args.rows < 1:
        parser.error('Positive row count required')
    with tempfile.TemporaryDirectory(prefix='aiwaf-log-profile-') as directory:
        path = Path(directory) / 'native.csv'
        samples = [aiwaf_rust.csv_log_profile(str(path), ['path', 'status'], ['/docs', '200'], False) for _ in range(args.rows)]
        with path.open(newline='') as file:
            assert len(list(csv.DictReader(file))) == args.rows
        py_times = []
        path = Path(directory) / 'python.csv'
        for i in range(args.rows):
            start = time.perf_counter()
            with path.open('a', newline='', encoding='utf-8') as file:
                writer = csv.writer(file)
                if i == 0: writer.writerow(['path', 'status'])
                writer.writerow(['/docs', '200'])
            py_times.append((time.perf_counter() - start) * 1000)
        cached_times = []
        cached = Path(directory) / 'cached.csv'
        aiwaf_rust.csv_log_append(str(cached), ['path', 'status'], ['/warm', '200'], False)
        for i in range(args.rows):
            start = time.perf_counter()
            aiwaf_rust.csv_log_append(str(cached), ['path', 'status'], ['/docs', '200'], False)
            cached_times.append((time.perf_counter() - start) * 1000)
        aiwaf_rust.csv_log_close(str(cached))
        with cached.open(newline='') as file:
            assert len(list(csv.DictReader(file))) == args.rows + 1
        report = dict(native_median_ms={name: statistics.median(row[i] for row in samples)
            for i, name in enumerate(['directory', 'open', 'lock', 'metadata', 'write_flush', 'fsync', 'close'])},
            native_total_median_ms=statistics.median(sum(row) for row in samples),
            python_total_median_ms=statistics.median(py_times), rows=args.rows, persisted_row_checks_passed=True,
            cached_native_median_ms=statistics.median(cached_times),
            scope='Uncontended synchronous append, fsync off; native cross-process locking, Python legacy writer unlocked.')
        print(json.dumps(report, indent=2))
        if args.output: args.output.write_text(json.dumps(report, indent=2), encoding='utf-8')
if __name__ == '__main__': main()
