from flask import Flask, jsonify
import pytest
from unittest.mock import patch

from aiwaf.flask import AIWAF, aiwaf_exempt_from


def _create_app(tmp_path, middlewares=None, config=None):
    app = Flask(__name__)
    app.config.update({
        'TESTING': True,
        'AIWAF_USE_CSV': True,
        'AIWAF_DATA_DIR': str(tmp_path),
        'AIWAF_EXEMPT_PATHS': set(),
        'AIWAF_ENABLE_LOGGING': False,
        'AIWAF_RATE_WINDOW': 60,
        'AIWAF_RATE_MAX': 100,
        'AIWAF_RATE_FLOOD': 200,
        'AIWAF_MIN_FORM_TIME': 1.0,
        'AIWAF_GEO_BLOCK_ENABLED': False,
        'AIWAF_GEO_BLOCK_COUNTRIES': [],
        'AIWAF_GEO_ALLOW_COUNTRIES': [],
    })
    if config:
        app.config.update(config)

    AIWAF(app, middlewares=middlewares)
    return app


def test_rate_limit_per_path_isolated(tmp_path):
    app = _create_app(
        tmp_path,
        middlewares=['rate_limit'],
        config={'AIWAF_RATE_MAX': 1, 'AIWAF_RATE_WINDOW': 60},
    )

    @app.route('/path-a')
    def path_a():
        return 'OK'

    @app.route('/path-b')
    def path_b():
        return 'OK'

    client = app.test_client()
    headers = {'User-Agent': 'Test Browser 1.0'}

    assert client.get('/path-a', headers=headers).status_code == 200
    assert client.get('/path-a', headers=headers).status_code == 429
    assert client.get('/path-b', headers=headers).status_code == 200


def test_rate_limit_legacy_ip_mode_affects_other_paths(tmp_path):
    app = _create_app(
        tmp_path,
        middlewares=['rate_limit'],
        config={
            'AIWAF_RATE_MAX': 1,
            'AIWAF_RATE_WINDOW': 60,
            'AIWAF_RATE_KEY_MODE': 'ip',
        },
    )

    @app.route('/path-a')
    def path_a_legacy():
        return 'OK'

    @app.route('/path-b')
    def path_b_legacy():
        return 'OK'

    client = app.test_client()
    headers = {'User-Agent': 'Test Browser 1.0'}

    assert client.get('/path-a', headers=headers).status_code == 200
    assert client.get('/path-a', headers=headers).status_code == 429
    # In legacy ip-only mode, /path-b shares the same bucket.
    assert client.get('/path-b', headers=headers).status_code == 429


def test_rate_limit_soft_blocklist_legacy_toggle(tmp_path):
    app = _create_app(
        tmp_path,
        middlewares=['rate_limit'],
        config={
            'AIWAF_RATE_MAX': 1,
            'AIWAF_RATE_WINDOW': 60,
            'AIWAF_RATE_SOFT_BLOCK_BLOCKLIST': True,
        },
    )

    @app.route('/throttle')
    def throttle():
        return 'OK'

    client = app.test_client()
    headers = {
        'User-Agent': 'Test Browser 1.0',
        'X-Forwarded-For': '203.0.113.210',
    }

    assert client.get('/throttle', headers=headers).status_code == 200
    assert client.get('/throttle', headers=headers).status_code == 429

    from aiwaf.flask.blocklist_manager import BlocklistManager
    with app.app_context():
        assert BlocklistManager.is_blocked('203.0.113.210')


def test_geo_block_exempt_route(tmp_path, monkeypatch):
    app = _create_app(
        tmp_path,
        middlewares=['geo_block'],
        config={
            'AIWAF_GEO_BLOCK_ENABLED': True,
            'AIWAF_GEO_BLOCK_COUNTRIES': ['US'],
        },
    )

    monkeypatch.setattr(
        'aiwaf.flask.geo_block_middleware.get_country_for_ip',
        lambda ip, config: 'US',
    )

    @app.route('/blocked')
    def blocked():
        return jsonify({'status': 'blocked'})

    @app.route('/exempted')
    @aiwaf_exempt_from('geo_block')
    def exempted():
        return jsonify({'status': 'exempted'})

    client = app.test_client()
    headers = {'User-Agent': 'Test Browser 1.0'}

    assert client.get('/blocked', headers=headers).status_code == 403
    assert client.get('/exempted', headers=headers).status_code == 200


def test_honeypot_blocks_fast_post(tmp_path):
    app = _create_app(
        tmp_path,
        middlewares=['honeypot'],
        config={'AIWAF_MIN_FORM_TIME': 5.0},
    )

    @app.route('/form', methods=['GET', 'POST'])
    def form():
        return 'OK'

    client = app.test_client()
    headers = {'User-Agent': 'Test Browser 1.0'}

    assert client.get('/form', headers=headers).status_code == 200
    assert client.post('/form', headers=headers).status_code == 403


@patch("time.time")
def test_honeypot_page_expired_returns_409(mock_time, tmp_path):
    app = _create_app(
        tmp_path,
        middlewares=['honeypot'],
        config={'AIWAF_MIN_FORM_TIME': 1.0, 'AIWAF_MAX_PAGE_TIME': 240},
    )

    @app.route('/form-expired', methods=['GET', 'POST'])
    def form_expired():
        return 'OK'

    client = app.test_client()
    headers = {'User-Agent': 'Test Browser 1.0'}

    mock_time.return_value = 1000.0
    assert client.get('/form-expired', headers=headers).status_code == 200
    mock_time.return_value = 1300.0
    resp = client.post('/form-expired', headers=headers)
    assert resp.status_code == 409
    payload = resp.get_json() or {}
    assert payload.get("reload_required") is True


def test_honeypot_get_to_obvious_post_only_returns_405(tmp_path):
    app = _create_app(tmp_path, middlewares=['honeypot'])

    @app.route('/api/create/', methods=['POST'])
    def create_only():
        return 'OK'

    client = app.test_client()
    headers = {'User-Agent': 'Test Browser 1.0'}
    assert client.get('/api/create/', headers=headers).status_code == 405


def test_honeypot_post_to_get_only_returns_405(tmp_path):
    app = _create_app(tmp_path, middlewares=['honeypot'])
    from aiwaf.flask.honeypot_timing_middleware import _aiwaf_cache
    _aiwaf_cache.clear()

    @app.route('/read-only', methods=['GET'])
    def read_only():
        return 'OK'

    client = app.test_client()
    headers = {'User-Agent': 'Test Browser 1.0'}
    assert client.post('/read-only', headers=headers).status_code == 405


def test_uuid_tamper_blocks_invalid(tmp_path):
    app = _create_app(tmp_path, middlewares=['uuid_tamper'])

    @app.route('/uuid')
    def uuid_route():
        return 'OK'

    client = app.test_client()
    headers = {'User-Agent': 'Test Browser 1.0'}

    assert client.get('/uuid?uuid=invalid', headers=headers).status_code == 403
    assert client.get(
        '/uuid?uuid=550e8400-e29b-41d4-a716-446655440000',
        headers=headers,
    ).status_code == 200


def test_ip_keyword_block_blocks_malicious_path(tmp_path):
    app = _create_app(tmp_path, middlewares=['ip_keyword_block'])

    @app.route('/safe')
    def safe():
        return 'OK'

    client = app.test_client()
    headers = {'User-Agent': 'Test Browser 1.0'}

    assert client.get('/safe', headers=headers).status_code == 200
    assert client.get('/.env', headers=headers).status_code == 403


def test_header_validation_blocks_missing_user_agent(tmp_path):
    app = _create_app(tmp_path, middlewares=['header_validation'])

    @app.route('/headers')
    def headers_route():
        return 'OK'

    client = app.test_client()

    assert client.get('/headers', headers={'User-Agent': ''}).status_code == 403
    assert client.get('/headers', headers={'User-Agent': 'short'}).status_code == 403
    assert client.get('/headers', headers={'User-Agent': 'Test Browser 1.0'}).status_code == 200


def test_path_rules_disable_header_validation_and_override_rate_limits(tmp_path):
    app = _create_app(
        tmp_path,
        middlewares=['header_validation', 'rate_limit'],
        config={
            'AIWAF_RATE_WINDOW': 60,
            'AIWAF_RATE_MAX': 1,
            'AIWAF_PATH_RULES': [
                {
                    'PREFIX': '/myapp/api/',
                    'DISABLE': ['HeaderValidationMiddleware'],
                    'RATE_LIMIT': {'MAX': 1000},
                },
                {
                    'PREFIX': '/myapp/',
                    'RATE_LIMIT': {'MAX': 1},
                },
            ],
        },
    )

    @app.route('/myapp/api/data')
    def api_data():
        return 'OK'

    @app.route('/myapp/ui')
    def ui():
        return 'OK'

    client = app.test_client()

    assert client.get('/myapp/api/data', headers={'User-Agent': ''}).status_code == 200
    assert client.get('/myapp/ui', headers={'User-Agent': ''}).status_code == 403

    from aiwaf.flask.rate_limit_middleware import _aiwaf_cache
    _aiwaf_cache.clear()

    headers = {'User-Agent': 'Test Browser 1.0'}
    assert client.get('/myapp/ui', headers=headers).status_code == 200
    assert client.get('/myapp/ui', headers=headers).status_code == 429

    assert client.get('/myapp/api/data', headers=headers).status_code == 200
    assert client.get('/myapp/api/data', headers=headers).status_code == 200


def test_ai_anomaly_burst_only_does_not_block(tmp_path, monkeypatch):
    np = pytest.importorskip("numpy")

    app = _create_app(
        tmp_path,
        middlewares=['ai_anomaly'],
        config={'AIWAF_WINDOW_SECONDS': 60},
    )

    @app.route('/poll')
    def poll():
        return 'OK'

    middleware = app.extensions["aiwaf"].middleware_instances.get('ai_anomaly')
    assert middleware is not None

    class DummyModel:
        def predict(self, X):
            return [-1]

    monkeypatch.setattr(middleware, "model", DummyModel())
    monkeypatch.setattr('aiwaf.flask.anomaly_middleware.NUMPY_AVAILABLE', True)
    monkeypatch.setattr('aiwaf.flask.anomaly_middleware.np', np)

    client = app.test_client()
    headers = {'User-Agent': 'Test Browser 1.0'}

    for _ in range(20):
        response = client.get('/poll', headers=headers)
        assert response.status_code == 200
