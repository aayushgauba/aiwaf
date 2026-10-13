"""Combined CSV geo decisions preserve denies, stored updates, and exemptions."""
import pytest
from flask import Flask
from aiwaf.core import rust_backend
from aiwaf.flask import geo_block_middleware as geo, storage


@pytest.fixture
def protected(tmp_path, monkeypatch):
    native = pytest.importorskip('aiwaf_rust')
    if not hasattr(native, 'csv_geo_policy'):
        pytest.skip('Requires rebuilt combined geo extension')
    monkeypatch.setattr(rust_backend, 'aiwaf_rust', native)
    app = Flask(__name__)
    app.config.update(AIWAF_USE_CSV=True, AIWAF_DATA_DIR=str(tmp_path),
        AIWAF_USE_RUST=True, AIWAF_GEO_BLOCK_ENABLED=True,
        AIWAF_GEO_BLOCK_COUNTRIES=['CN'], AIWAF_EXEMPT_PATHS=[])
    monkeypatch.setattr(geo, 'get_country_for_ip', lambda *_: 'US')
    geo.GeoBlockMiddleware(app)
    app.add_url_rule('/docs', view_func=lambda: 'ok')
    return app, native


def test_combined_dynamic_country_update_and_allow_precedence(protected):
    app, _ = protected
    client = app.test_client()
    assert client.get('/docs', environ_base={'REMOTE_ADDR': '203.0.113.8'}).status_code == 200
    with app.app_context():
        storage.add_geo_blocked_country('US')
    assert client.get('/docs', environ_base={'REMOTE_ADDR': '203.0.113.9'}).status_code == 403
    app.config['AIWAF_GEO_ALLOW_COUNTRIES'] = ['US']
    assert client.get('/docs', environ_base={'REMOTE_ADDR': '203.0.113.10'}).status_code == 200


def test_geo_one_boundary_and_exempt_hook_order(protected, monkeypatch):
    app, native = protected
    calls = []
    def combined(*args):
        calls.append(args)
        return native.csv_geo_policy(*args)
    monkeypatch.setattr(geo, 'csv_function', lambda name: combined if name == 'csv_geo_policy' else None)
    client = app.test_client()
    assert client.get('/docs', environ_base={'REMOTE_ADDR': '203.0.113.11'}).status_code == 200
    assert len(calls) == 1
    app.config['AIWAF_EXEMPT_PATHS'] = ['/docs']
    assert client.get('/docs', environ_base={'REMOTE_ADDR': '203.0.113.12'}).status_code == 200
    assert len(calls) == 1


def test_geo_disabled_and_old_extension_fallback(protected, monkeypatch):
    app, _ = protected
    app.config['AIWAF_USE_RUST'] = False
    app.config['AIWAF_GEO_ALLOW_COUNTRIES'] = ['GB']
    assert app.test_client().get('/docs', environ_base={'REMOTE_ADDR': '203.0.113.13'}).status_code == 403
    app.config['AIWAF_USE_RUST'] = True
    monkeypatch.setattr(geo, 'csv_function', lambda _: None)
    assert app.test_client().get('/docs', environ_base={'REMOTE_ADDR': '203.0.113.14'}).status_code == 403


def test_no_policy_does_not_resolve_geoip(protected, monkeypatch):
    app, _ = protected
    app.config['AIWAF_GEO_BLOCK_COUNTRIES'] = []
    def unexpected(*_):
        raise AssertionError('GeoIP should not run without configured or stored policy')
    monkeypatch.setattr(geo, 'get_country_for_ip', unexpected)
    assert app.test_client().get('/docs', environ_base={'REMOTE_ADDR': '203.0.113.15'}).status_code == 200


def test_combined_csv_failure_propagates(protected, monkeypatch):
    app, _ = protected
    app.config['TESTING'] = True
    def unavailable(*_):
        raise OSError('CSV unavailable')
    monkeypatch.setattr(geo, 'csv_function', lambda name: unavailable if name == 'csv_geo_policy' else None)
    with pytest.raises(OSError, match='CSV unavailable'):
        app.test_client().get('/docs', environ_base={'REMOTE_ADDR': '203.0.113.16'})
