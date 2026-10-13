"""Compare previous and combined request checks; no live traffic or AI fitting."""
import argparse
import json
from pathlib import Path
import statistics
import tempfile
import time

import aiwaf_rust as native
from aiwaf.core import sql_injection


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--requests', type=int, default=1000)
    parser.add_argument('--runs', type=int, default=3)
    parser.add_argument('--output', type=Path)
    args = parser.parse_args()
    if args.requests < 1 or args.runs < 1:
        parser.error('Positive request and run counts required')
    policy = sql_injection.SQLInjectionPolicy()
    original_dispatch = sql_injection.native_function
    results = []
    with tempfile.TemporaryDirectory() as directory:
        geo_file = str(Path(directory) / 'countries.csv')
        native.csv_write(geo_file, ['country', 'added_date'], [['US', 'date'], ['CN', 'date']], False)
        for scenario in ('sql_single', 'sql_100_fields', 'sql_early_attack', 'geo_csv'):
            body = ('ordinary value' if scenario == 'sql_single' else
                    {f'field{i}': 'ordinary value' for i in range(100)})
            if scenario == 'sql_early_attack':
                body['last'] = "x'--"
            samples = {'previous': [], 'combined': []}
            expected = None
            for trial in range(args.runs):
                for mode in (['previous', 'combined'] if trial % 2 == 0 else ['combined', 'previous']):
                    sql_injection.native_function = lambda name: (None if mode == 'previous' and name == 'policy_sql_signatures' else getattr(native, name, None))
                    def check():
                        if scenario != 'geo_csv':
                            return policy.inspect(body=body)
                        if mode == 'combined':
                            return native.csv_geo_policy(geo_file, 'US', set(), {'GB'})
                        return native.policy_geo('US', set(), {'GB'}, native.csv_read_set(geo_file, 'country', True))
                    for _ in range(10):
                        result = check()
                    if expected is None:
                        expected = result
                    assert result == expected
                    start = time.perf_counter()
                    for _ in range(args.requests):
                        assert check() == expected
                    samples[mode].append((time.perf_counter() - start) / args.requests)
            medians = {mode: statistics.median(values) for mode, values in samples.items()}
            results.append(dict(scenario=scenario, median_seconds=medians,
                previous_over_combined=medians['previous'] / medians['combined']))
    sql_injection.native_function = original_dispatch
    report = dict(requests=args.requests, runs=args.runs, results=results,
        scope='Synchronous SQL policy and CSV geo binding checks, warmed caches; no network, complete middleware chain, model scoring, or concurrency.')
    print(json.dumps(report, indent=2))
    if args.output:
        args.output.write_text(json.dumps(report, indent=2), encoding='utf-8')


if __name__ == '__main__':
    main()
