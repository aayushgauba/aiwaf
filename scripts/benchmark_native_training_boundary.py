"""Measure timestamps and the real native model boundary; compare seeded states."""
import argparse
from datetime import datetime, timedelta
import json
from pathlib import Path
import statistics
import time
import aiwaf_rust as native
from aiwaf.core.native_runtime import native_override
from aiwaf.core.training_pipeline import convert_training_fields, anomaly_statistics

def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--records', type=int, default=10000)
    parser.add_argument('--runs', type=int, default=3)
    parser.add_argument('--output', type=Path)
    args = parser.parse_args()
    if args.records < 1 or args.runs < 1: parser.error('Positive counts required')
    base = datetime(2026, 1, 1)
    records = [dict(ip=str(i % 50), path='/wp-content/shell.php' if i % 3 else '/docs',
        timestamp=base + timedelta(seconds=i), status='404' if i % 3 else '200', response_time=(i % 100) / 1000) for i in range(args.records)]
    results = []
    for fmt in ['apache_dates', 'iso_dates', 'model_boundary']:
        samples = {'previous': [], 'native': []}
        expected = None
        for trial in range(args.runs):
            for mode in (['previous', 'native'] if trial % 2 == 0 else ['native', 'previous']):
                if fmt == 'model_boundary':
                    model = native.IsolationForest(n_estimators=20, random_state=42)
                    start = time.perf_counter()
                    parameters = (records, {'/docs': False, '/wp-content/shell.php': True}, {}, ['200', '404'], ['shell', '.php'])
                    if mode == 'native':
                        batch = native.extract_native_training_features(*parameters)
                        outcome = batch.fit_predict(model)
                    else:
                        features = native.extract_raw_features(*parameters)
                        columns = ['path_len', 'kw_hits', 'resp_time', 'status_idx', 'burst_count', 'total_404']
                        matrix = [[float(row[key]) for key in columns] for row in features]
                        model.fit(matrix)
                        outcome = anomaly_statistics(features, model.predict(matrix))
                    seconds = time.perf_counter() - start
                    state = (outcome, model.to_json())
                else:
                    apache = fmt == 'apache_dates'
                    fields = [('1.1.1.1', row['timestamp'].strftime('%d/%b/%Y:%H:%M:%S +0000') if apache else row['timestamp'].isoformat(), '/path', '200', .1) for row in records]
                    with native_override(mode == 'native'):
                        start = time.perf_counter()
                        state = convert_training_fields(fields, apache=apache, prefer_native_iso=True)
                        seconds = time.perf_counter() - start
                if expected is None: expected = state
                assert state == expected
                samples[mode].append(seconds)
        medians = {mode: statistics.median(values) for mode, values in samples.items()}
        result = dict(scenario=fmt, median_seconds=medians, previous_over_native=medians['previous'] / medians['native'], samples_seconds=samples)
        results.append(result)
        print(json.dumps(result), flush=True)
    report = dict(records=args.records, runs=args.runs, equivalence_checks_passed=True,
                  scope='Unique timestamps; native-vs-Python parsing and real Rust feature/model fitting boundary. Both model modes fit the same Rust forest. No CSV I/O or network.', results=results)
    if args.output: args.output.write_text(json.dumps(report, indent=2), encoding='utf-8')

if __name__ == '__main__': main()
