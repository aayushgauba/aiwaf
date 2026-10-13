import pytest
from fastapi import FastAPI, Request
from fastapi.testclient import TestClient
from aiwaf.core.runtime_config import AIWAFConfig
from aiwaf.core.runtime_fastapi import AIWAF
from aiwaf.fast.middleware.ip_and_keyword_block_middleware import IPAndKeywordBlockMiddleware


@pytest.mark.parametrize('enabled', [False, True])
def test_fast_engine_sql_and_body_replay(tmp_path, enabled):
    native = pytest.importorskip('aiwaf_rust')
    if not hasattr(native, 'NativeRequestEngine'):
        pytest.skip('Requires compiled request engine')
    app = FastAPI()
    @app.api_route('/safe', methods=['GET', 'POST'])
    async def safe(request: Request):
        return await request.json() if request.method == 'POST' else {'ok': True}
    cfg = AIWAFConfig(load_from_env=False)
    cfg.set('storage.backend', 'csv')
    cfg.set('storage.file_path', str(tmp_path / 'runtime.csv'))
    cfg.set('AIWAF_RUST_REQUEST_ENGINE', enabled)
    AIWAF(app, config=cfg, middlewares=['ip_keyword_block'])
    client = TestClient(app)
    assert client.get('/safe').status_code == 200
    node = app.middleware_stack
    while not isinstance(node, IPAndKeywordBlockMiddleware):
        node = node.app
    if enabled:
        assert hasattr(node, '_native_request_engine_profile')
    assert client.get('/safe?q=1+UNION+SELECT').status_code == 403
    response = client.post('/safe', json={'field': 'original body'})
    assert response.status_code == 200 and response.json() == {'field': 'original body'}
    assert client.post('/safe', json={'field': '1 UNION SELECT'}).status_code == 403
    assert client.get('/shell.php').status_code == 403

