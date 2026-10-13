"""Opt-in compiled stage preserves request bodies and standard responses."""
import pytest
from flask import Flask, request
from aiwaf.core.storage_csv_impl import ensure_all
from aiwaf.flask.ip_and_keyword_block_middleware import IPAndKeywordBlockMiddleware


@pytest.mark.parametrize('enabled', [False, True])
def test_flask_engine_route_sql_body_and_learning(tmp_path, enabled):
    native = pytest.importorskip('aiwaf_rust')
    if not hasattr(native, 'NativeRequestEngine'):
        pytest.skip('Requires compiled request engine')
    ensure_all(tmp_path)
    app = Flask(__name__)
    app.config.update(AIWAF_USE_CSV=True, AIWAF_USE_RUST=True, AIWAF_RUST_CSV=True,
        AIWAF_DATA_DIR=str(tmp_path), AIWAF_EXEMPT_PATHS=[], AIWAF_RUST_REQUEST_ENGINE=enabled)
    app.add_url_rule('/safe', endpoint='safe', view_func=lambda: request.get_json(silent=True) or {'ok': True}, methods=['GET', 'POST'])
    middleware = IPAndKeywordBlockMiddleware(app)
    client = app.test_client()
    assert client.get('/safe').status_code == 200
    if enabled:
        assert hasattr(middleware, '_native_request_engine_profile')
    assert client.get('/safe?q=1+UNION+SELECT').status_code == 403
    response = client.post('/safe', json={'field': 'original body'})
    assert response.status_code == 200 and response.json == {'field': 'original body'}
    assert client.post('/safe', json={'field': '1 UNION SELECT'}).status_code == 403
    assert client.get('/shell/admin.php?x=shell-script').status_code == 403


def test_oversized_query_rejected_before_query_key_extraction(tmp_path):
    from flask import Request
    class RejectQueryParsing(Request):
        @property
        def args(self):
            pytest.fail('Parsed an oversized query')
    ensure_all(tmp_path)
    app = Flask(__name__)
    app.request_class = RejectQueryParsing
    app.config.update(AIWAF_USE_CSV=True, AIWAF_DATA_DIR=str(tmp_path), AIWAF_EXEMPT_PATHS=[],
        AIWAF_RUST_REQUEST_ENGINE=True, AIWAF_PAYLOAD_MAX_BYTES=8)
    IPAndKeywordBlockMiddleware(app)
    assert app.test_client().get('/safe?q=' + 'x' * 100).status_code == 413

