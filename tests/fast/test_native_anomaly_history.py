"""FastAPI native histories preserve cache lifecycle and live configuration."""
import pytest
from fastapi import FastAPI
from fastapi.testclient import TestClient
from aiwaf.core import rust_backend
from aiwaf.core.runtime_config import AIWAFConfig
from aiwaf.core.runtime_storage import initialize_storage
from aiwaf.fast.middleware.anomaly_middleware import AIAnomalyMiddleware


def test_fast_retained_history_and_live_disable(monkeypatch):
    native = pytest.importorskip('aiwaf_rust')
    if not hasattr(native, 'NativeAnomalyHistory'):
        pytest.skip('Requires rebuilt anomaly extension')
    monkeypatch.setattr(rust_backend, 'aiwaf_rust', native)
    monkeypatch.setattr(AIAnomalyMiddleware, '_persist_training_log', lambda *_: None)
    initialize_storage('memory')
    app = FastAPI()
    app.state.aiwaf_config = AIWAFConfig(load_from_env=False)
    app.add_api_route('/docs', lambda: {'ok': True})
    app.add_middleware(AIAnomalyMiddleware)
    app.middleware_stack = app.build_middleware_stack()
    middleware = app.middleware_stack
    while not isinstance(middleware, AIAnomalyMiddleware):
        middleware = middleware.app
    middleware.model = native.IsolationForest(n_estimators=10, random_state=42)
    middleware.model.fit([[8., 0., .01, 0., float(i), 0.] for i in range(20)])
    client = TestClient(app)
    assert client.get('/docs').status_code == 200
    assert client.get('/docs').status_code == 200
    key = next(iter(middleware.request_cache))
    assert isinstance(middleware.request_cache[key], native.NativeAnomalyHistory)
    assert len(middleware.request_cache[key]) == 2
    app.state.aiwaf_config.set('AIWAF_RUST_ANOMALY_HISTORY', False)
    assert client.get('/docs').status_code == 200
    assert isinstance(middleware.request_cache[key], list)
    assert len(middleware.request_cache[key]) == 3
    middleware.request_cache['expired'] = [(0., '/old', 404, .1)]
    middleware._history_cleanup_at = 0.
    assert client.get('/docs').status_code == 200
    assert 'expired' not in middleware.request_cache
