"""Flask retains native histories only with a supported Rust model."""
import pytest
from flask import Flask
from aiwaf.core import rust_backend
from aiwaf.flask.anomaly_middleware import AIAnomalyMiddleware


def test_flask_retained_history_and_live_disable(tmp_path, monkeypatch):
    native = pytest.importorskip('aiwaf_rust')
    if not hasattr(native, 'NativeAnomalyHistory'):
        pytest.skip('Requires rebuilt anomaly extension')
    monkeypatch.setattr(rust_backend, 'aiwaf_rust', native)
    monkeypatch.setattr(AIAnomalyMiddleware, '_load_model', lambda *_: None)
    monkeypatch.setattr(AIAnomalyMiddleware, '_check_ai_status_periodically', lambda *_: None)
    monkeypatch.setattr(AIAnomalyMiddleware, '_persist_training_log', lambda *_: None)
    app = Flask(__name__)
    app.config.update(AIWAF_USE_CSV=True, AIWAF_DATA_DIR=str(tmp_path), AIWAF_EXEMPT_PATHS=[])
    app.add_url_rule('/docs', view_func=lambda: 'ok')
    middleware = AIAnomalyMiddleware(app)
    middleware.model = native.IsolationForest(n_estimators=10, random_state=42)
    middleware.model.fit([[8., 0., .01, 0., float(i), 0.] for i in range(20)])
    client = app.test_client()
    for _ in range(2):
        assert client.get('/docs', environ_base={'REMOTE_ADDR': '203.0.113.27'}).status_code == 200
    history = middleware.request_cache['aiwaf:203.0.113.27']
    assert isinstance(history, native.NativeAnomalyHistory)
    assert len(history) == 2
    app.config['AIWAF_RUST_ANOMALY_HISTORY'] = False
    assert client.get('/docs', environ_base={'REMOTE_ADDR': '203.0.113.27'}).status_code == 200
    assert isinstance(middleware.request_cache['aiwaf:203.0.113.27'], list)
    assert len(middleware.request_cache['aiwaf:203.0.113.27']) == 3
    middleware.request_cache['expired'] = [(0., '/old', 404, .1)]
    middleware._history_cleanup_at = 0.
    assert client.get('/docs', environ_base={'REMOTE_ADDR': '203.0.113.27'}).status_code == 200
    assert 'expired' not in middleware.request_cache


def test_flask_route_adapter_reused_and_route_changes_visible(monkeypatch):
    from unittest.mock import patch
    from werkzeug.routing import Map, Rule
    app = Flask(__name__)
    app.add_url_rule('/items/<int:item>', view_func=lambda item: str(item), methods=['POST'])
    middleware = AIAnomalyMiddleware()
    with app.test_request_context('/items/42'):
        with patch.object(app.url_map, 'bind', wraps=app.url_map.bind) as bind:
            assert middleware._route_exists('/items/42')
            assert not middleware._route_exists('/missing')
            assert middleware._route_exists('/items/43')
            assert bind.call_count == 1
            app.url_map.add(Rule('/added', endpoint='added'))
            assert middleware._route_exists('/added')
            assert bind.call_count == 1
        app.url_map = Map([Rule('/replacement', endpoint='replacement')])
        assert middleware._route_exists('/replacement')
        assert not middleware._route_exists('/items/42')
    with app.test_request_context('/replacement'):
        with patch.object(app.url_map, 'bind', wraps=app.url_map.bind) as bind:
            assert middleware._route_exists('/replacement')
            assert bind.call_count == 1
