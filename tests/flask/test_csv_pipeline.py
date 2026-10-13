import pytest
from flask import Flask, request
from aiwaf.flask.csv_pipeline import NativeAIWAF
from aiwaf.flask.exemption_decorators import aiwaf_exempt, aiwaf_require_protection


def app_for(tmp_path, **config):
    app = Flask(__name__)
    @app.route('/echo', methods=['GET', 'POST'])
    def echo():
        return {'body': request.get_data().decode(), 'ok': True}
    @app.route('/exempt')
    @aiwaf_exempt
    def exempt():
        return {'ok': True}
    @app.route('/required')
    @aiwaf_exempt
    @aiwaf_require_protection('ip_keyword_block')
    def required():
        return {'ok': True}
    NativeAIWAF(app, {'data_dir': str(tmp_path), 'rate_max':10000, 'rate_flood':20000,
                     'min_form_time':0, 'required_headers':[], **config})
    return app


def test_native_flask_body_replay_and_policy_order(tmp_path, monkeypatch):
    from aiwaf.core import ip_keyword, sql_injection
    monkeypatch.setattr(ip_keyword, 'evaluate_keyword_policy', lambda *a, **k: pytest.fail('Python keyword fallback'))
    monkeypatch.setattr(sql_injection.SQLInjectionPolicy, 'inspect', lambda *a, **k: pytest.fail('Python SQL fallback'))
    app = app_for(tmp_path)
    client = app.test_client()
    assert client.post('/echo', json={'field':'value'}).json['body'] == '{"field": "value"}'
    assert client.get('/echo?q=union+select').status_code == 403
    assert client.post('/echo', json={'field':'uni\u006fn select'}).status_code == 403
    assert client.get('/wp-content/plugins/pods/init.php').status_code == 403
    assert app.extensions['aiwaf_csv_pipeline'].pipeline.native.processed_requests == 4


def test_native_flask_decorators_and_limit(tmp_path):
    client = app_for(tmp_path, max_bytes=30).test_client()
    assert client.get('/exempt?q=union+select').status_code == 200
    assert client.get('/required?q=union+select').status_code == 403
    assert client.post('/echo', data='x'*31, content_type='application/json').status_code == 413


def test_native_flask_stream_uninspected_body_and_unknown_route(tmp_path):
    client = app_for(tmp_path).test_client()
    assert client.post('/echo', data='union select', content_type='application/octet-stream').json['body'] == 'union select'
    assert client.get('/ordinary-missing-page').status_code == 404
    assert client.post('/echo', data='a=hello&b=world', content_type='application/x-www-form-urlencoded').json['body'] == 'a=hello&b=world'
