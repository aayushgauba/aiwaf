"""Offline full Flask middleware-chain smoke check across CSV-sharing processes."""
import argparse
from concurrent.futures import ProcessPoolExecutor
import csv
import json
import logging
from pathlib import Path
import tempfile


def worker(data_dir, worker_id, requests):
    from flask import Flask
    from aiwaf.flask.flask_integration import AIWAF
    logging.disable(logging.CRITICAL)
    app = Flask(__name__)
    app.secret_key = 'offline-validation-only'
    app.config.update(AIWAF_DATA_DIR=str(Path(data_dir) / 'data'), AIWAF_USE_CSV=True,
        AIWAF_USE_RUST=True, AIWAF_RUST_CSV=True, AIWAF_EXEMPT_PATHS=[],
        AIWAF_LOG_FORMAT='csv', AIWAF_LOG_DIR=str(Path(data_dir) / 'logs'))
    app.add_url_rule('/docs', 'docs', lambda: 'ok')
    waf = AIWAF(app, middlewares=list(AIWAF.AVAILABLE_MIDDLEWARES))
    enabled = set(waf.get_enabled_middlewares())
    if enabled != set(AIWAF.AVAILABLE_MIDDLEWARES):
        raise RuntimeError(f'Missing middleware hooks: {enabled}')
    client = app.test_client()
    headers = {'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/122.0.0.0 Safari/537.36',
               'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8',
               'Accept-Language': 'en-US,en;q=0.9', 'Accept-Encoding': 'gzip, deflate', 'Connection': 'keep-alive'}
    for i in range(requests):
        allowed = client.get('/docs', headers=headers, environ_base={'REMOTE_ADDR': f'198.51.{worker_id}.{i + 1}'})
        if allowed.status_code != 200:
            raise RuntimeError(f'Allowed response: {allowed.status_code}')
        blocked = client.get('/wp-content/plugins/pods/init.php', headers=headers,
                             environ_base={'REMOTE_ADDR': f'203.0.{worker_id}.{i + 1}'})
        if blocked.status_code != 403:
            raise RuntimeError(f'Probe response: {blocked.status_code}')
    return sorted(enabled)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--workers', type=int, default=4)
    parser.add_argument('--requests', type=int, default=20)
    parser.add_argument('--output', type=Path)
    args = parser.parse_args()
    if not 1 <= args.workers <= 32 or not 1 <= args.requests <= 250:
        parser.error('workers=1..32 and requests=1..250 required')
    from aiwaf.core import storage_csv_impl
    from aiwaf.core.native_runtime import csv_function
    if csv_function('csv_keywords_update') is None:
        parser.error('Install the matching native wheel first')
    with tempfile.TemporaryDirectory(prefix='aiwaf-release-') as directory:
        # Create files before workers start so initialization is outside contention.
        storage_csv_impl.ensure_all(Path(directory) / 'data')
        (Path(directory) / 'logs').mkdir()
        with ProcessPoolExecutor(max_workers=args.workers) as executor:
            futures = [executor.submit(worker, directory, i, args.requests) for i in range(args.workers)]
            enabled = [future.result(timeout=120) for future in futures]
        with (Path(directory) / 'logs' / 'access.log').open(newline='', encoding='utf-8') as file:
            rows = list(csv.DictReader(file))
        expected = args.workers * args.requests
        if len(rows) != expected * 2 or sum(row['status_code'] == '403' for row in rows) != expected:
            raise RuntimeError('Missing or corrupted access log rows')
        blocked = storage_csv_impl.read_blocklist(Path(directory) / 'data')
        if len(blocked) != expected:
            raise RuntimeError('Lost shared blocklist updates')
        report = dict(workers=args.workers, allowed_requests=expected, blocked_requests=expected,
            log_rows=len(rows), persisted_blocked_ips=len(blocked), enabled_middlewares=enabled[0],
            checks_passed=True, scope=__doc__ + ' GET requests only; geo has no blocked-country policy, UUID and honeypot have no matching signals. Rate cache is the default per-worker memory cache. No HTTP server or production site.')
        print(json.dumps(report, indent=2))
        if args.output:
            args.output.write_text(json.dumps(report, indent=2), encoding='utf-8')


if __name__ == '__main__':
    main()
