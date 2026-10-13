"""Matched localhost HTTP comparison of a published wheel and a development build."""
import argparse
import asyncio
from collections import Counter
import json
import logging
import os
from pathlib import Path
import socket
import statistics
import subprocess
import sys
import tempfile
import time
import uuid

GET_IPS = [f'8.8.8.{i + 1}' for i in range(16)]
POST_IPS = [f'9.9.9.{i + 1}' for i in range(16)]
IPS = GET_IPS + POST_IPS
ITEM = str(uuid.UUID('12345678-1234-4234-8234-123456789abc'))
PATH = '/items/' + ITEM
HEADERS = {'user-agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 Chrome/126.0.0.0 Safari/537.36',
           'accept': 'application/json', 'accept-language': 'en-US,en;q=0.9', 'accept-encoding': 'gzip, deflate', 'referer': 'http://localhost/'}
urlpatterns = []


class TimedApplication:
    """Record complete ASGI application time only for marked measured requests."""
    def __init__(self, app):
        self.app = app
        self.durations = []

    async def __call__(self, scope, receive, send):
        if scope['type'] == 'http' and scope['path'] == '/__benchmark_metrics':
            body = json.dumps({'server_ms': self.durations}).encode()
            await send({'type': 'http.response.start', 'status': 200, 'headers': [(b'content-type', b'application/json')]})
            await send({'type': 'http.response.body', 'body': body})
            return
        measured = scope['type'] == 'http' and (b'x-benchmark-measured', b'1') in scope['headers']
        start = time.perf_counter() if measured else None
        try:
            await self.app(scope, receive, send)
        finally:
            if measured:
                self.durations.append((time.perf_counter() - start) * 1000)


def build_plain_app(framework, data):
    """Same tiny handlers and framework/server adapter, with no AIWAF middleware."""
    if framework == 'flask':
        from flask import Flask, jsonify
        from uvicorn.middleware.wsgi import WSGIMiddleware
        app = Flask(__name__)
        app.add_url_rule('/items/<uuid:item>', endpoint='items', view_func=lambda item: jsonify(ok=True), methods=['GET', 'POST'])
        app.add_url_rule('/docs', endpoint='docs', view_func=lambda: jsonify(ok=True))
        app.add_url_rule('/__benchmark_state', endpoint='benchmark_state', view_func=lambda: jsonify(ai_model_active=False, history_type=None))
        return WSGIMiddleware(app)
    if framework == 'fastapi':
        from fastapi import FastAPI
        app = FastAPI(docs_url=None, redoc_url=None)
        app.add_api_route('/items/{item}', lambda item: {'ok': True}, methods=['GET', 'POST'])
        app.add_api_route('/docs', lambda: {'ok': True})
        app.add_api_route('/__benchmark_state', lambda: {'ai_model_active': False, 'history_type': None})
        return app
    from django.conf import settings
    settings.configure(SECRET_KEY='local-benchmark-only', DEBUG=False, ALLOWED_HOSTS=['*'], ROOT_URLCONF=__name__,
        INSTALLED_APPS=['django.contrib.auth', 'django.contrib.contenttypes', 'aiwaf.django'],
        DATABASES={'default': {'ENGINE': 'django.db.backends.sqlite3', 'NAME': str(data / 'django.sqlite3')}},
        MIDDLEWARE=[])
    import django
    django.setup()
    from django.core.management import call_command
    call_command('migrate', verbosity=0)
    from django.http import JsonResponse
    from django.urls import path
    global urlpatterns
    urlpatterns = [path('items/<uuid:item>', lambda request, item: JsonResponse({'ok': True})),
        path('docs', lambda request: JsonResponse({'ok': True})),
        path('__benchmark_state', lambda request: JsonResponse({'ai_model_active': False, 'history_type': None}))]
    from django.core.wsgi import get_wsgi_application
    from uvicorn.middleware.wsgi import WSGIMiddleware
    return WSGIMiddleware(get_wsgi_application())


def find_middleware(chain, cls):
    pending, seen = [chain], set()
    while pending:
        value = pending.pop()
        if id(value) in seen:
            continue
        seen.add(id(value))
        if isinstance(value, cls):
            return value
        for name in ['get_response', '__wrapped__']:
            child = getattr(value, name, None)
            if child is not None:
                pending.append(child)
        for cell in getattr(value, '__closure__', None) or ():
            pending.append(cell.cell_contents)
    raise RuntimeError('Anomaly middleware missing from live Django chain')


def seed_history():
    now = time.time()
    return [(now - 20 - i * .1, PATH, 200, .005) for i in range(200)]


def build_native_app(framework, data, model, honeypot_backend='csv'):
    config = {'data_dir': str(data), 'exempt_paths': [], 'rate_max':1000000,
        'rate_flood':2000000, 'min_form_time':0., 'geo_block':['KP'],
        'log_path':str(data / 'requests.csv'), 'honeypot_backend':honeypot_backend}
    def runtime_state(pipeline):
        return {'ai_model_active': pipeline.native.diagnostics()[0], 'history_type':'Rust-owned',
                'engine_processed': pipeline.native.processed_requests}
    if framework == 'flask':
        from flask import Flask, jsonify
        from aiwaf.flask.csv_pipeline import NativeAIWAF
        from uvicorn.middleware.wsgi import WSGIMiddleware
        app = Flask(__name__)
        app.add_url_rule('/items/<uuid:item>', endpoint='items', view_func=lambda item: jsonify(ok=True), methods=['GET', 'POST'])
        app.add_url_rule('/docs', endpoint='docs', view_func=lambda: jsonify(ok=True))
        pipeline = NativeAIWAF(app, config=config, model=model).pipeline
        app.add_url_rule('/__benchmark_state', endpoint='state', view_func=lambda: jsonify(runtime_state(pipeline)))
        application = WSGIMiddleware(app)
    elif framework == 'fastapi':
        from fastapi import FastAPI
        from aiwaf.fast.csv_pipeline import NativeAIWAFMiddleware
        app = FastAPI(docs_url=None, redoc_url=None)
        app.add_api_route('/items/{item}', lambda item: {'ok':True}, methods=['GET', 'POST'])
        app.add_api_route('/docs', lambda: {'ok':True})
        app.add_middleware(NativeAIWAFMiddleware, config=config, model=model)
        app.middleware_stack = app.build_middleware_stack()
        node = app.middleware_stack
        while not isinstance(node, NativeAIWAFMiddleware):
            node = node.app
        pipeline = node.pipeline
        app.add_api_route('/__benchmark_state', lambda: runtime_state(pipeline))
        application = app
    else:
        from django.conf import settings
        settings.configure(SECRET_KEY='local-benchmark-only', DEBUG=False, ALLOWED_HOSTS=['*'], ROOT_URLCONF=__name__,
            INSTALLED_APPS=['django.contrib.auth', 'django.contrib.contenttypes', 'aiwaf.django'],
            DATABASES={'default': {'ENGINE':'django.db.backends.sqlite3', 'NAME':str(data / 'django.sqlite3')}},
            AIWAF_CSV_PIPELINE=config, AIWAF_CSV_PIPELINE_MODEL=model,
            MIDDLEWARE=['aiwaf.django.csv_pipeline.NativeAIWAFMiddleware'])
        import django
        django.setup()
        logging.getLogger('django.request').addHandler(logging.StreamHandler())
        from django.http import JsonResponse
        from django.urls import path
        from django.core.wsgi import get_wsgi_application
        from uvicorn.middleware.wsgi import WSGIMiddleware
        from aiwaf.django.csv_pipeline import NativeAIWAFMiddleware
        if os.getenv('AIWAF_BENCHMARK_TRACE') == '1':
            original_call = NativeAIWAFMiddleware.__call__
            def traced_call(instance, request):
                try:
                    return original_call(instance, request)
                except BaseException:
                    import traceback
                    traceback.print_exc()
                    raise
            NativeAIWAFMiddleware.__call__ = traced_call
        global urlpatterns
        urlpatterns = [path('items/<uuid:item>', lambda request, item: JsonResponse({'ok':True})),
                       path('docs', lambda request: JsonResponse({'ok':True}))]
        handler = get_wsgi_application()
        pipeline = find_middleware(handler._middleware_chain, NativeAIWAFMiddleware).pipeline
        urlpatterns.append(path('__benchmark_state', lambda request: JsonResponse(runtime_state(pipeline))))
        application = WSGIMiddleware(handler)
    for ip in IPS:
        pipeline.native.seed_history(ip, [(t, path, status, rt, False) for t, path, status, rt in seed_history()])
    return application


def build_app(framework, ai, data, plain=False, engine=False, pipeline=False, honeypot_backend='csv'):
    import aiwaf
    import aiwaf_rust
    if plain:
        return build_plain_app(framework, data), {'python_source': aiwaf.__file__, 'python_version': aiwaf.__version__,
            'rust_source': aiwaf_rust.__file__, 'native_histories_available': hasattr(aiwaf_rust, 'NativeAnomalyHistory'),
            'enabled_middlewares': [], 'ai_model': None}
    from aiwaf.core.storage_csv_impl import ensure_all, rewrite_blacklist
    ensure_all(data)
    rewrite_blacklist(data, {f'198.18.{i // 256}.{i % 256}': {'reason': 'benchmark fixture', 'permanent': True} for i in range(1000)})
    model = None
    if ai:
        model = aiwaf_rust.IsolationForest(n_estimators=100, random_state=42, contamination=.1)
        model.fit([[40+i%10, 0., .001+i%5/1000, i%13, i%8, 0.] for i in range(128)])
    middlewares = ['geo_block', 'ip_keyword_block', 'rate_limit', 'ai_anomaly', 'honeypot', 'uuid_tamper', 'header_validation', 'logging']
    if pipeline:
        return build_native_app(framework, data, model, honeypot_backend), {'python_source': aiwaf.__file__, 'python_version':aiwaf.__version__,
            'rust_source':aiwaf_rust.__file__, 'enabled_middlewares':middlewares,
            'ai_model':'100-tree seeded Rust IsolationForest' if ai else None, 'native_csv_pipeline':True,
            'honeypot_backend':honeypot_backend}
    if framework == 'flask':
        from flask import Flask, jsonify
        from aiwaf.flask.flask_integration import AIWAF
        from uvicorn.middleware.wsgi import WSGIMiddleware
        app = Flask(__name__)
        app.config.update(AIWAF_USE_CSV=True, AIWAF_USE_RUST=True, AIWAF_RUST_CSV=True, AIWAF_DATA_DIR=str(data),
            AIWAF_EXEMPT_PATHS=[], AIWAF_RATE_MAX=1000000, AIWAF_RATE_FLOOD=2000000,
            AIWAF_MIN_FORM_TIME=0.,
            AIWAF_FORCE_AI=bool(ai),
            AIWAF_RUST_REQUEST_ENGINE=bool(engine),
            AIWAF_GEO_BLOCK_ENABLED=True, AIWAF_GEO_BLOCK_COUNTRIES=['KP'],
            AIWAF_LOG_DIR=str(data / 'logs'), AIWAF_LOG_FORMAT='csv', AIWAF_MIDDLEWARE_LOGGING=True)
        app.add_url_rule('/items/<uuid:item>', endpoint='items', view_func=lambda item: jsonify(ok=True), methods=['GET', 'POST'])
        app.add_url_rule('/docs', endpoint='docs', view_func=lambda: jsonify(ok=True))
        waf = AIWAF(app, middlewares=middlewares)
        anomaly = waf.middleware_instances['ai_anomaly']
        anomaly.model = model
        for ip in IPS:
            anomaly.request_cache['aiwaf:' + ip] = seed_history()
        app.add_url_rule('/__benchmark_state', endpoint='benchmark_state', view_func=lambda: jsonify(
            ai_model_active=anomaly.model is not None,
            history_type=type(anomaly.request_cache.get('aiwaf:' + GET_IPS[0], [])).__name__,
            engine_processed=getattr(getattr(waf.middleware_instances['ip_keyword_block'], '_native_request_engine_profile', (None, None))[1], 'processed_requests', 0)))
        application = WSGIMiddleware(app)
        enabled = sorted(waf.get_enabled_middlewares())
    elif framework == 'fastapi':
        from fastapi import FastAPI
        from aiwaf.core.runtime_config import AIWAFConfig
        from aiwaf.core.runtime_fastapi import AIWAF
        from aiwaf.fast.middleware.anomaly_middleware import AIAnomalyMiddleware
        app = FastAPI(docs_url=None, redoc_url=None)
        app.add_api_route('/items/{item}', lambda item: {'ok': True}, methods=['GET', 'POST'])
        app.add_api_route('/docs', lambda: {'ok': True})
        cfg = AIWAFConfig(load_from_env=False)
        for key, value in {'storage.backend': 'csv', 'storage.file_path': str(data / 'runtime_store.csv'),
            'AIWAF_USE_RUST': True, 'AIWAF_RUST_CSV': True, 'rate_limiting.max_requests': 1000000,
            'AIWAF_RUST_REQUEST_ENGINE': bool(engine),
            'rate_limiting.flood_threshold': 2000000, 'exemptions.private_ips_exempted': False,
            'exemptions.localhost_exempted': False, 'exemptions.auto_exempt_patterns': [],
            'geo_block.enabled': True, 'geo_block.block_countries': ['KP'],
            'honeypot.min_form_time': 0.,
            'logging_middleware.log_dir': str(data / 'logs'), 'logging_middleware.log_format': 'csv'}.items():
            cfg.set(key, value)
        requested = [name if name not in ('rate_limit', 'logging') else {'rate_limit': 'rate_limiting', 'logging': 'logging_middleware'}[name] for name in middlewares]
        waf = AIWAF(app, config=cfg, middlewares=requested)
        app.middleware_stack = app.build_middleware_stack()
        node = app.middleware_stack
        while not isinstance(node, AIAnomalyMiddleware):
            node = node.app
        node.model = model
        from aiwaf.fast.middleware.ip_and_keyword_block_middleware import IPAndKeywordBlockMiddleware
        keyword_node = app.middleware_stack
        while not isinstance(keyword_node, IPAndKeywordBlockMiddleware):
            keyword_node = keyword_node.app
        for ip in IPS:
            node.request_cache['aiwaf:' + ip] = seed_history()
        app.add_api_route('/__benchmark_state', lambda: {'ai_model_active': node.model is not None,
            'history_type': type(node.request_cache.get('aiwaf:' + GET_IPS[0], [])).__name__,
            'engine_processed': getattr(getattr(keyword_node, '_native_request_engine_profile', (None, None))[1], 'processed_requests', 0)})
        application = app
        enabled = [m.cls.__name__ for m in app.user_middleware]
    else:
        from django.conf import settings
        settings.configure(SECRET_KEY='local-benchmark-only', DEBUG=False, ALLOWED_HOSTS=['*'], ROOT_URLCONF=__name__,
            INSTALLED_APPS=['django.contrib.auth', 'django.contrib.contenttypes', 'aiwaf.django'],
            DATABASES={'default': {'ENGINE': 'django.db.backends.sqlite3', 'NAME': str(data / 'django.sqlite3')}},
            CACHES={'default': {'BACKEND': 'django.core.cache.backends.locmem.LocMemCache', 'LOCATION': 'benchmark'}},
            AIWAF_STORAGE_MODE='csv', AIWAF_DATA_DIR=str(data), AIWAF_USE_RUST=True, AIWAF_RUST_CSV=True,
            AIWAF_RUST_REQUEST_ENGINE=bool(engine),
            AIWAF_EXEMPT_PATHS=[], AIWAF_RATE_MAX=1000000, AIWAF_RATE_FLOOD=2000000, AIWAF_MIN_AI_LOGS=0,
            AIWAF_MIN_FORM_TIME=0.,
            AIWAF_GEO_BLOCK_ENABLED=True, AIWAF_GEO_BLOCK_COUNTRIES=['KP'],
            AIWAF_MIDDLEWARE_LOGGING=True, AIWAF_MIDDLEWARE_CSV=True, AIWAF_MIDDLEWARE_DB=False,
            AIWAF_MIDDLEWARE_LOG=str(data / 'requests.csv'),
            MIDDLEWARE=['aiwaf.django.middleware.' + name for name in ['GeoBlockMiddleware', 'IPAndKeywordBlockMiddleware',
                'RateLimitMiddleware', 'AIAnomalyMiddleware', 'HoneypotTimingMiddleware', 'UUIDTamperMiddleware', 'HeaderValidationMiddleware']]
                + ['aiwaf.django.middleware_logger.AIWAFLoggerMiddleware'])
        import django
        django.setup()
        from django.core.management import call_command
        call_command('migrate', verbosity=0)
        from django.http import JsonResponse
        from django.urls import path
        global urlpatterns
        urlpatterns = [path('items/<uuid:item>', lambda request, item: JsonResponse({'ok': True})),
                       path('docs', lambda request: JsonResponse({'ok': True}))]
        from aiwaf.django import middleware
        middleware.MODEL = model
        from django.core.cache import cache
        for ip in IPS:
            cache.set('aiwaf:' + ip, seed_history(), timeout=60)
        from django.core.wsgi import get_wsgi_application
        from uvicorn.middleware.wsgi import WSGIMiddleware
        handler = get_wsgi_application()
        anomaly = find_middleware(handler._middleware_chain, middleware.AIAnomalyMiddleware)
        keyword_node = find_middleware(handler._middleware_chain, middleware.IPAndKeywordBlockMiddleware)
        urlpatterns.append(path('__benchmark_state', lambda request: JsonResponse(
            {'ai_model_active': anomaly.model is not None, 'history_type': type(cache.get('aiwaf:' + GET_IPS[0], [])).__name__,
             'engine_processed': getattr(getattr(keyword_node, '_native_request_engine_profile', (None, None))[1], 'processed_requests', 0)})))
        application = WSGIMiddleware(handler)
        enabled = settings.MIDDLEWARE
    return application, {'python_source': aiwaf.__file__, 'python_version': aiwaf.__version__, 'rust_source': aiwaf_rust.__file__,
        'native_histories_available': hasattr(aiwaf_rust, 'NativeAnomalyHistory'), 'enabled_middlewares': enabled,
        'ai_model': '100-tree seeded Rust IsolationForest' if ai else None, 'compiled_request_engine': bool(engine)}


async def traffic(port, count, concurrency, ai, plain=False, engine=False):
    import httpx
    latencies, statuses = [], Counter()
    params = {f'field{i}': f'value{i}' for i in range(30)}
    async with httpx.AsyncClient(base_url=f'http://127.0.0.1:{port}', headers=HEADERS, trust_env=False,
            limits=httpx.Limits(max_connections=concurrency, max_keepalive_connections=concurrency), timeout=60.) as client:
        for _ in range(200):
            try:
                response = await client.get('/docs', headers={'x-forwarded-for': GET_IPS[0]})
                if response.status_code == 200:
                    break
                raise RuntimeError(f'Warmup HTTP {response.status_code}: {response.text[:200]}')
            except httpx.ConnectError:
                await asyncio.sleep(.05)
        else:
            raise RuntimeError('Server never started')
        for i in range(32):
            response = await client.get(PATH, params=params, headers={'x-forwarded-for': GET_IPS[i % len(GET_IPS)]})
            if response.status_code != 200:
                raise RuntimeError(f'Warmup failed: {response.status_code} {response.text[:200]}')
        state = await client.get('/__benchmark_state', headers={'x-forwarded-for': GET_IPS[0]})
        assert state.status_code == 200 and state.json()['ai_model_active'] == bool(ai), state.text
        runtime_state = state.json()
        if engine:
            assert runtime_state.get('engine_processed', 0) > 0, runtime_state
        async def worker(index):
            for i in range(index, count, concurrency):
                cohort = GET_IPS if i % 5 else POST_IPS
                headers = {'x-forwarded-for': cohort[i % len(cohort)], 'x-benchmark-measured': '1'}
                start = time.perf_counter()
                if i % 5:
                    response = await client.get(PATH, params=params, headers=headers)
                else:
                    response = await client.post(PATH, json=params, headers=headers)
                latencies.append((time.perf_counter() - start) * 1000)
                statuses[response.status_code] += 1
                if response.status_code != 200:
                    raise RuntimeError(f'Measured request {i} returned {response.status_code}: {response.text[:200]}')
        start = time.perf_counter()
        await asyncio.gather(*(worker(i) for i in range(concurrency)))
        elapsed = time.perf_counter() - start
        if statuses != {200: count}:
            raise RuntimeError(f'Unexpected measured responses: {statuses}')
        for _ in range(100):
            timing_response = await client.get('/__benchmark_metrics')
            server_times = timing_response.json()['server_ms']
            if len(server_times) == count:
                break
            await asyncio.sleep(.01)
        assert len(server_times) == count, len(server_times)
        probes = {}
        for name, path, params in [('php_scan', '/wp-content/plugins/pods/init.php', {}),
                                   ('sql_injection', PATH, {'id': "1 UNION SELECT password FROM users--"})]:
            response = await client.get(path, params=params, headers={'x-forwarded-for': '8.26.56.1' if name == 'php_scan' else '8.26.56.2'})
            probes[name] = response.status_code
        expected = {'php_scan': 404, 'sql_injection': 200} if plain else {'php_scan': 403, 'sql_injection': 403}
        if probes != expected:
            raise RuntimeError(f'Protection probe failed: {probes}')
    ordered = sorted(latencies)
    return {'requests_per_second': count / elapsed, 'elapsed_seconds': elapsed, 'p50_ms': statistics.median(ordered),
        'p95_ms': ordered[int((len(ordered)-1)*.95)], 'p99_ms': ordered[int((len(ordered)-1)*.99)],
        'mean_http_ms': statistics.mean(latencies), 'mean_server_ms': statistics.mean(server_times),
        'p50_server_ms': statistics.median(server_times), 'p95_server_ms': sorted(server_times)[int((count-1)*.95)],
        'statuses': dict(statuses), 'probes': probes, 'verified_runtime_state': runtime_state}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--serve', action='store_true')
    parser.add_argument('--framework', choices=['flask', 'django', 'fastapi'], default='flask')
    parser.add_argument('--ai', type=int, choices=[0, 1], default=0)
    parser.add_argument('--plain', action='store_true', help='Run the identical framework endpoint without AIWAF middleware')
    parser.add_argument('--engine', action='store_true', help='Enable the experimental compiled SQL/keyword stage')
    parser.add_argument('--pipeline', action='store_true', help='Use the complete Rust-owned CSV pipeline')
    parser.add_argument('--honeypot-backend', choices=['csv','memory'], default='csv', help='Native pipeline form-timing state backend')
    parser.add_argument('--port', type=int)
    parser.add_argument('--data', type=Path)
    parser.add_argument('--requests', type=int, default=600)
    parser.add_argument('--concurrency', type=int, default=16)
    parser.add_argument('--output', type=Path, required=True)
    args = parser.parse_args()
    if args.requests < 1 or args.concurrency < 1:
        parser.error('Positive request and concurrency counts required')
    if args.plain and args.ai:
        parser.error('Plain endpoints have no AI model')
    if args.pipeline and (args.plain or args.engine):
        parser.error('Choose pipeline, engine or plain independently')
    if args.honeypot_backend != 'csv' and not args.pipeline:
        parser.error('The honeypot backend option requires --pipeline')
    # Keep error tracebacks available when a correctness gate fails.
    logging.disable(logging.WARNING)
    if args.serve:
        import uvicorn
        app, metadata = build_app(args.framework, bool(args.ai), args.data, args.plain, args.engine, args.pipeline, args.honeypot_backend)
        (args.data / 'metadata.json').write_text(json.dumps(metadata))
        uvicorn.run(TimedApplication(app), host='127.0.0.1', port=args.port, log_level='critical', access_log=False,
                    log_config=None, lifespan='off', proxy_headers=True, forwarded_allow_ips='127.0.0.1')
        return
    with tempfile.TemporaryDirectory(prefix='aiwaf-http-release-') as directory:
        data = Path(directory)
        with socket.socket() as sock:
            sock.bind(('127.0.0.1', 0))
            port = sock.getsockname()[1]
        command = [sys.executable, __file__, '--serve', '--framework', args.framework, '--ai', str(args.ai),
                   '--data', str(data), '--port', str(port), '--output', str(args.output)]
        if args.plain:
            command.append('--plain')
        if args.engine:
            command.append('--engine')
        if args.pipeline:
            command.append('--pipeline')
            command.extend(['--honeypot-backend', args.honeypot_backend])
        with (data / 'server.log').open('w') as server_log:
            process = subprocess.Popen(command, stdout=server_log, stderr=server_log)
            try:
                result = asyncio.run(traffic(port, args.requests, args.concurrency, args.ai, args.plain, args.engine or args.pipeline))
                result.update(json.loads((data / 'metadata.json').read_text()))
            except Exception:
                print((data / 'server.log').read_text(), file=sys.stderr)
                for csv_file in data.rglob('*.csv'):
                    import csv
                    with csv_file.open(newline='') as stream:
                        tail = list(csv.reader(stream))[-2:]
                    print(str(csv_file) + ': ' + str(tail)[:2500], file=sys.stderr)
                raise
            finally:
                process.terminate()
                try:
                    process.wait(timeout=10)
                except subprocess.TimeoutExpired:
                    process.kill()
                    process.wait()
        result.update(framework=args.framework, ai=bool(args.ai), plain=args.plain, pipeline=args.pipeline, requests=args.requests, concurrency=args.concurrency)
        args.output.write_text(json.dumps(result, indent=2))
        print(json.dumps(result), flush=True)


if __name__ == '__main__':
    main()
