from flask import Flask, request
from aiwaf.flask import storage, utils
from aiwaf.core import rust_backend
import pytest


def test_request_reuse_observes_file_and_config_updates(tmp_path, monkeypatch):
    native = pytest.importorskip('aiwaf_rust')
    monkeypatch.setattr(rust_backend, 'aiwaf_rust', native)
    app = Flask(__name__)
    app.config.update(AIWAF_DATA_DIR=str(tmp_path), AIWAF_USE_CSV=True, AIWAF_EXEMPT_PATHS=[])
    calls = []
    original = utils.csv_function
    def counted(name):
        function = original(name)
        return lambda *args: (calls.append(name), function(*args))[1]
    monkeypatch.setattr(utils, 'csv_function', counted)
    with app.test_request_context('/unknown', environ_base={'REMOTE_ADDR': '127.0.0.1'}):
        assert not utils.is_exempt(request)
        assert not utils.is_exempt(request)
        assert calls == ['csv_request_exempt']
        storage.add_path_exemption('/unknown')
        assert utils.is_exempt(request)
        storage.remove_path_exemption('/unknown')
        assert not utils.is_exempt(request)
        app.config['AIWAF_EXEMPT_PATHS'] = ['/unknown']
        assert utils.is_exempt(request)
        app.config['AIWAF_EXEMPT_PATHS'] = []
        storage.add_ip_whitelist('127.0.0.1')
        assert utils.is_exempt(request)
    with app.test_request_context('/unknown', environ_base={'REMOTE_ADDR': '127.0.0.1'}):
        assert utils.is_exempt(request)
        assert len(calls) == 6
