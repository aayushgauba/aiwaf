import csv
import json
from flask import Flask
from aiwaf.flask import AIWAF
from aiwaf.flask.cli import AIWAFManager
from aiwaf.core import storage_csv_impl as policy


def test_flask_startup_and_cli_import_legacy_runtime_policies(tmp_path, monkeypatch):
    source = tmp_path / 'runtime_store.csv'
    with source.open('w', newline='') as stream:
        writer = csv.writer(stream)
        writer.writerow(['key', 'value', 'expires_at'])
        writer.writerow(['blocked:203.0.113.9', json.dumps('old block'), ''])
        writer.writerow(['keyword_counts', json.dumps({'old-keyword': 3}), ''])
    original = source.read_bytes()
    app = Flask(__name__)
    app.config['AIWAF_DATA_DIR'] = str(tmp_path)
    app.add_url_rule('/safe', view_func=lambda: 'ok')
    AIWAF(app, middlewares=['ip_keyword_block'])
    assert app.test_client().get('/safe', environ_overrides={'REMOTE_ADDR': '203.0.113.9'}).status_code == 403
    assert policy.read_keywords(tmp_path) == {'old-keyword'}
    monkeypatch.setenv('AIWAF_DATA_DIR', str(tmp_path))
    manager = AIWAFManager(str(tmp_path))
    assert 'old-keyword' in manager.storage['read_keywords']()
    assert '203.0.113.9' in manager.storage['read_blacklist']()
    assert source.read_bytes() == original
