"""Native cache delegation exercised through both real framework adapters."""
import json
from unittest.mock import patch

import pytest

from aiwaf.core.honeypot_cache import HoneypotCache, RedisHoneypotCache
from aiwaf.core.csv_pipeline import CSVPipeline


class Cache:
    def __init__(self):
        self.values = {}
        self.timeout = None
        self.error = False

    def get(self, key):
        if self.error:
            raise ConnectionError('private-cache-password')
        return self.values.get(key)

    def set(self, key, value, *, timeout):
        if self.error:
            raise ConnectionError('private-cache-password')
        self.values[key] = value
        self.timeout = timeout


def make_client(framework, directory, cache, **config):
    config = {'data_dir': str(directory), 'enabled': ['honeypot'],
              'honeypot_backend': 'cache', 'exempt_paths': [], **config}
    if framework == 'flask':
        from flask import Flask
        from aiwaf.flask.csv_pipeline import NativeAIWAF
        app = Flask(__name__)
        app.add_url_rule('/form', 'form', lambda: {'ok': True}, methods=['GET', 'POST'])
        NativeAIWAF(app, config, honeypot_cache=cache)
        return app.test_client()
    from fastapi import FastAPI
    from fastapi.testclient import TestClient
    from aiwaf.fast.csv_pipeline import NativeAIWAFMiddleware
    app = FastAPI()
    app.add_api_route('/form', lambda: {'ok': True}, methods=['GET', 'POST'])
    app.add_middleware(NativeAIWAFMiddleware, config=config, honeypot_cache=cache)
    return TestClient(app)


@pytest.fixture(params=['flask', 'fastapi'])
def framework(request):
    return request.param


def test_shared_get_post_timing_and_expiry(framework, tmp_path):
    cache = Cache()
    first = make_client(framework, tmp_path / 'first', cache)
    second = make_client(framework, tmp_path / 'second', cache)
    with patch('aiwaf.core.csv_pipeline.time.time', return_value=1000):
        assert first.get('/form').status_code == 200
    assert cache.timeout == 300
    assert not (tmp_path / 'first' / 'pipeline_state.csv').exists()
    for now, status in [(1000.1, 403), (1002, 200), (1250, 409), (1301, 200)]:
        with patch('aiwaf.core.csv_pipeline.time.time', return_value=now):
            assert second.post('/form').status_code == status


def test_cache_failure_is_generic_503_and_exemptions_skip_io(framework, tmp_path):
    cache = Cache()
    client = make_client(framework, tmp_path / 'active', cache)
    cache.error = True
    for method in ('get', 'post'):
        response = getattr(client, method)('/form')
        assert response.status_code == 503
        body = response.content if framework == 'fastapi' else response.data
        assert b'private-cache-password' not in body
    exempt = make_client(framework, tmp_path / 'exempt', cache, exempt_paths=['/form'])
    assert exempt.get('/form').status_code == 200
    disabled = make_client(framework, tmp_path / 'disabled', cache, enabled=[])
    assert disabled.get('/form').status_code == 200


@pytest.mark.parametrize('value', ['bad', [True, 2000], [float('nan'), 2000], [1000, 999]])
def test_malformed_cache_fails_closed(framework, tmp_path, value):
    cache = Cache()
    cache.get = lambda key: value
    client = make_client(framework, tmp_path, cache)
    assert client.post('/form').status_code == 503


def test_false_write_and_async_result_fail_closed(framework, tmp_path):
    cache = Cache()
    cache.set = lambda *a, **k: False
    client = make_client(framework, tmp_path, cache)
    assert client.get('/form').status_code == 503
    async def result():
        return None
    cache.get = lambda key: result()
    assert client.post('/form').status_code == 503


def test_config_validation_and_bounded_namespaced_keys(tmp_path):
    with pytest.raises(ValueError, match='requires a honeypot_cache'):
        CSVPipeline({'data_dir': str(tmp_path), 'honeypot_backend': 'cache'})
    with pytest.raises(ValueError, match='honeypot_redis_url'):
        CSVPipeline({'data_dir': str(tmp_path), 'honeypot_backend': 'redis'})
    with pytest.raises(ValueError, match='requires honeypot_backend'):
        CSVPipeline({'data_dir': str(tmp_path)}, honeypot_cache=Cache())
    async def get(key):
        return None
    cache = Cache()
    cache.get = get
    with pytest.raises(TypeError, match='synchronous'):
        HoneypotCache(cache)
    first, second = HoneypotCache(Cache(), namespace='site1'), HoneypotCache(Cache(), namespace='site2')
    assert first.key('::1') != second.key('::1')
    assert len(first.key('x' * 10000)) < 250


def test_redis_strict_serialization_expiry_and_secret_removal(tmp_path):
    class Redis:
        def __init__(self):
            self.values = {}
        def get(self, key):
            return self.values.get(key)
        def setex(self, key, ttl, value):
            assert ttl == 300
            self.values[key] = value.encode()
            return True
    redis = Redis()
    with patch('aiwaf.core.honeypot_cache._redis_from_url', return_value=redis):
        pipeline = CSVPipeline({'data_dir': str(tmp_path), 'honeypot_backend': 'redis',
                                'honeypot_redis_url': 'redis://:secret@localhost/0'})
        assert 'secret' not in json.dumps(pipeline.profile)
        cache = HoneypotCache(RedisHoneypotCache('redis://localhost/0'))
        cache.set_timestamp('8.8.8.8', 1000, 1300, 300)
        assert cache.get_timestamp('8.8.8.8') == (1000, 1300)
        redis.values[cache.key('8.8.8.8')] = b'broken-json'
        with pytest.raises(ValueError):
            cache.get_timestamp('8.8.8.8')


def test_fastapi_cache_io_runs_off_the_event_loop(tmp_path):
    import asyncio
    import threading
    import httpx
    from fastapi import FastAPI
    from aiwaf.fast.csv_pipeline import NativeAIWAFMiddleware
    cache = Cache()
    thread_ids = []
    original = cache.set
    def set_value(*args, **kwargs):
        thread_ids.append(threading.get_ident())
        return original(*args, **kwargs)
    cache.set = set_value
    app = FastAPI()
    app.add_api_route('/form', lambda: {'ok': True})
    app.add_middleware(NativeAIWAFMiddleware, config={'data_dir': str(tmp_path),
        'enabled': ['honeypot'], 'honeypot_backend': 'cache', 'exempt_paths': []}, honeypot_cache=cache)
    async def run():
        event_loop_thread = threading.get_ident()
        async with httpx.AsyncClient(transport=httpx.ASGITransport(app=app), base_url='http://testserver') as client:
            assert (await client.get('/form')).status_code == 200
        assert thread_ids and all(t != event_loop_thread for t in thread_ids)
    asyncio.run(run())
