import csv
import json
from fastapi import FastAPI
from fastapi.testclient import TestClient
from aiwaf.core.runtime_config import AIWAFConfig
from aiwaf.core.runtime_fastapi import AIWAF
from aiwaf.core.runtime_storage import get_blocklist_store, get_exemption_store
from aiwaf.core import storage_csv_impl as policy


def test_fastapi_migrated_blocks_and_shared_flask_policy(tmp_path):
    source = tmp_path / 'runtime_store.csv'
    with source.open('w', newline='') as stream:
        writer = csv.writer(stream)
        writer.writerow(['key', 'value', 'expires_at'])
        writer.writerow(['blocked:203.0.113.9', json.dumps('old block'), ''])
    original = source.read_bytes()
    app = FastAPI()
    app.add_api_route('/safe', lambda: {'ok': True})
    config = AIWAFConfig(load_from_env=False)
    config.set('storage.backend', 'csv')
    config.set('storage.data_dir', str(tmp_path))
    config.set('exemptions.auto_exempt_private_ips', False)
    AIWAF(app, config=config, middlewares=['ip_keyword_block'])
    client = TestClient(app, client=('203.0.113.9', 12345))
    assert client.get('/safe').status_code == 403
    assert get_blocklist_store().is_blocked('203.0.113.9')
    policy.append_allowlist(tmp_path, '203.0.113.9')
    assert get_exemption_store().is_exempted('203.0.113.9')
    assert client.get('/safe').status_code == 200
    assert source.read_bytes() == original
