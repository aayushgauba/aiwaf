"""Profile and compare request-time anomaly work using a real seeded Rust forest."""
import argparse
import json
from pathlib import Path
import statistics
import time
import aiwaf_rust
from aiwaf.core import anomaly


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--requests', type=int, default=100)
    parser.add_argument('--runs', type=int, default=3)
    parser.add_argument('--output', type=Path)
    args = parser.parse_args()
    if args.requests < 1 or args.runs < 1:
        parser.error('Positive counts required')
    model = aiwaf_rust.IsolationForest(n_estimators=100, random_state=42, contamination=.1)
    model.fit([[10 + i % 10, i % 2, .01 + i % 4 / 1000, i % 3, 1 + i % 4, i % 2] for i in range(128)])
    keywords = ['.php', 'wp-', 'admin', 'shell']
    results = []
    original_dispatch = anomaly.native_function
    for scenario, count in [(scenario, count) for scenario in ('anomalous', 'benign') for count in (20, 200, 1000)]:
        history = ([(100 - i / max(count, 1) * 40, '/wp-content/admin/shell.php', 404, .1) for i in range(count)]
            if scenario == 'anomalous' else [(100-i if i < 3 else 80 - i / max(count, 1) * 20, '/user/home', 200, .01) for i in range(count)])
        kwargs = dict(ip='203.0.113.1', path='/wp-content/admin/shell.php' if scenario == 'anomalous' else '/user/home',
            status_code=404 if scenario == 'anomalous' else 200,
            response_time=.1 if scenario == 'anomalous' else .01, now=101., window_seconds=60., model=model,
            static_keywords=keywords, malicious_keywords=keywords, keyword_learning_enabled=False,
            path_exists=lambda _: False, is_exempt_path=lambda _: False, is_malicious_context=lambda _: True)
        features = anomaly.build_feature_vector(path=kwargs['path'], status_code=kwargs['status_code'], response_time=kwargs['response_time'],
            now=101, history=history, static_keywords=keywords, path_exists_current=False, is_exempt_path_current=False)
        stages = {}
        payload = [{'path_lower': p.lower(), 'timestamp': t, 'status': status, 'kw_check': True} for t, p, status, _ in history]
        for name, call in {
            'trim_and_features': lambda: anomaly.build_feature_vector(path=kwargs['path'], status_code=kwargs['status_code'],
                response_time=kwargs['response_time'], now=101, history=anomaly.trim_history(history, now=101, window_seconds=60),
                static_keywords=keywords, path_exists_current=False, is_exempt_path_current=False),
            'forest_prediction': lambda: anomaly.predict_anomaly(model, features),
            'payload_conversion': lambda: [{'path_lower': p.lower(), 'timestamp': t, 'status': status, 'kw_check': True} for t, p, status, _ in history],
            'rust_recent_analysis': lambda: aiwaf_rust.analyze_recent_behavior(payload, keywords),
        }.items():
            samples = []
            for _ in range(args.runs):
                start = time.perf_counter()
                for _ in range(args.requests): call()
                samples.append((time.perf_counter() - start) / args.requests)
            stages[name] = statistics.median(samples)
        modes = {'previous': history}
        if hasattr(aiwaf_rust, 'NativeAnomalyHistory'):
            modes['tuple_analysis'] = history
            modes['native_history'] = aiwaf_rust.NativeAnomalyHistory(history)
        timings = {mode: [] for mode in modes}
        expected = None
        for trial in range(args.runs):
            order = list(modes) if trial % 2 == 0 else list(reversed(modes))
            for mode in order:
                anomaly.native_function = (lambda name: None if name == 'analyze_recent_tuples' else original_dispatch(name)) if mode == 'previous' else original_dispatch
                state = modes[mode]
                outcome = anomaly.evaluate_anomaly(history=state, **kwargs)
                comparable = (outcome.block, outcome.reason, outcome.learned_keywords, list(outcome.updated_history))
                if expected is None: expected = comparable
                assert comparable == expected
                start = time.perf_counter()
                for _ in range(args.requests): anomaly.evaluate_anomaly(history=state, **kwargs)
                timings[mode].append((time.perf_counter() - start) / args.requests)
        results.append(dict(scenario=scenario, history_entries=count, prediction=anomaly.predict_anomaly(model, features),
            stage_seconds=stages, median_seconds={m: statistics.median(v) for m, v in timings.items()}))
    anomaly.native_function = original_dispatch
    report = dict(requests=args.requests, runs=args.runs, trees=100, contamination=.1, results=results,
        scope='Isolated completed-response anomaly evaluation, fixed per-client history and real seeded Rust forest. No HTTP server, CSV writes, networking, or concurrent load.')
    print(json.dumps(report, indent=2))
    if args.output: args.output.write_text(json.dumps(report, indent=2), encoding='utf-8')


if __name__ == '__main__':
    main()
