"""FastAPI integration checks for combined canonical CSV geo policy."""
from fastapi import FastAPI
from fastapi.testclient import TestClient
import pytest
from aiwaf.core import rust_backend
from aiwaf.core.runtime_storage import initialize_storage, get_geo_block_store
from aiwaf.fast.middleware import geo_block_middleware as geo


@pytest.fixture
def protected(tmp_path, monkeypatch):
    native = pytest.importorskip('aiwaf_rust')
    if not hasattr(native, 'csv_geo_policy'):
        pytest.skip('Requires rebuilt geo extension')
    monkeypatch.setattr(rust_backend, 'aiwaf_rust', native)
    initialize_storage('csv', file_path=str(tmp_path / 'runtime.csv'))
    monkeypatch.setattr(geo, 'get_country_for_ip', lambda _: 'US')
    app = FastAPI()
    app.add_middleware(geo.GeoBlockMiddleware, enabled=True, block_countries=['CN'])
    app.add_api_route('/private', lambda: {'ok': True})
    return app, native


def test_geo_csv_changes_and_allow_precedence(protected):
    app, _ = protected
    client = TestClient(app)
    assert client.get('/private').status_code == 200
    get_geo_block_store().add_country('US')
    assert client.get('/private').status_code == 403
    get_geo_block_store().remove_country('US')
    assert client.get('/private').status_code == 200
    other = FastAPI()
    other.add_middleware(geo.GeoBlockMiddleware, enabled=True, allow_countries=['US'], block_countries=['US'])
    other.add_api_route('/private', lambda: {'ok': True})
    get_geo_block_store().add_country('US')
    assert TestClient(other).get('/private').status_code == 200


def test_fast_geo_exemptions_and_disabled_rust(protected, monkeypatch):
    app, native = protected
    get_geo_block_store().add_country('US')
    app.add_api_route('/health', lambda: {'ok': True})
    monkeypatch.setattr(native, 'csv_geo_policy', lambda *_: (_ for _ in ()).throw(AssertionError('Native should be disabled')))
    assert TestClient(app).get('/health').status_code == 200
    other = FastAPI()
    other.add_middleware(geo.GeoBlockMiddleware, enabled=True, block_countries=['CN'], use_rust=False)
    other.add_api_route('/private', lambda: {'ok': True})
    assert TestClient(other).get('/private').status_code == 403


def test_fast_geo_dynamic_only_and_old_extension(protected, monkeypatch):
    _, native = protected
    get_geo_block_store().add_country('US')
    monkeypatch.delattr(native, 'csv_geo_policy')
    for configured in ([], ['CN']):
        app = FastAPI()
        app.add_middleware(geo.GeoBlockMiddleware, enabled=True, block_countries=configured)
        app.add_api_route('/private', lambda: {'ok': True})
        assert TestClient(app).get('/private').status_code == 403


def test_fast_geo_uses_one_combined_call(protected, monkeypatch):
    app, native = protected
    original = native.csv_geo_policy
    calls = []
    def combined(*args):
        calls.append(args)
        return original(*args)
    monkeypatch.setattr(native, 'csv_geo_policy', combined)
    assert TestClient(app).get('/private').status_code == 200
    assert len(calls) == 1


def test_fast_orchestrator_passes_disabled_rust_flag(protected, monkeypatch):
    _, native = protected
    from aiwaf.fast import AIWAF
    from aiwaf.core.runtime_config import AIWAFConfig
    store = get_geo_block_store()
    store.add_country('US')
    config = AIWAFConfig(load_from_env=False)
    config.set('storage.backend', 'csv')
    config.set('storage.file_path', str(store.storage.file_path))
    config.set('geo_block.enabled', True)
    config.set('geo_block.block_countries', ['CN'])
    config.set('AIWAF_USE_RUST', False)
    monkeypatch.setattr(native, 'csv_geo_policy', lambda *_: (_ for _ in ()).throw(AssertionError('Configured Rust disable ignored')))
    app = FastAPI()
    app.add_api_route('/private', lambda: {'ok': True})
    AIWAF(app, config=config, middlewares=['geo_block'])
    assert TestClient(app).get('/private').status_code == 403
