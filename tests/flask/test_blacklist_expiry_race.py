"""Listing must not overwrite a blacklist changed by another worker."""
import time
import sys
import pytest
from pathlib import Path
from flask import Flask
from aiwaf.flask import cli, storage
from aiwaf.core import storage_csv_impl as policy


@pytest.mark.parametrize('old_ips', [['203.0.113.9'], ['203.0.113.1', '203.0.113.2']])
def test_cli_expiry_filter_preserves_concurrently_trained_blocks(tmp_path, monkeypatch, old_ips):
    monkeypatch.setenv('AIWAF_DATA_DIR', str(tmp_path))
    expired = {'reason': 'old block', 'expires_at': time.time() - 1,
               'blocked_at': time.time() - 901, 'duration': 900}
    policy.rewrite_blacklist(tmp_path, {ip: expired for ip in old_ips})
    read = policy.read_blacklist
    app = Flask(__name__)
    app.config.update(AIWAF_USE_CSV=True, AIWAF_DATA_DIR=str(tmp_path))
    def read_then_train(directory):
        snapshot = read(directory)
        # A concurrent trainer commits after the CLI's read, before its cleanup.
        with app.app_context():
            storage.add_ip_blacklist('203.0.113.1', 'Excessive 404s')
            storage.add_ip_blacklist('203.0.113.2', 'Excessive 404s')
        return snapshot
    monkeypatch.setattr(policy, 'read_blacklist', read_then_train)
    backend = cli.get_storage_instance()
    backend['read_blacklist']()
    actual = read(tmp_path)
    assert {'203.0.113.1', '203.0.113.2'} <= set(actual)
    monkeypatch.setattr(policy, 'read_blacklist', read)
    assert {'203.0.113.1', '203.0.113.2'} <= set(backend['read_blacklist']())


def test_cli_listing_filters_expired_rows_without_rewriting_the_file(tmp_path, monkeypatch):
    monkeypatch.setenv('AIWAF_DATA_DIR', str(tmp_path))
    policy.rewrite_blacklist(tmp_path, {'203.0.113.9': {
        'reason': 'old block', 'expires_at': time.time() - 1,
        'blocked_at': time.time() - 901, 'duration': 900}})
    path = tmp_path / 'blacklist.csv'
    before = path.read_bytes()
    assert cli.get_storage_instance()['read_blacklist']() == {}
    assert path.read_bytes() == before


def test_cli_displays_canonical_block_date(tmp_path, monkeypatch, capsys):
    policy.rewrite_blacklist(tmp_path, {'203.0.113.1': {
        'reason': 'test block', 'expires_at': time.time() + 900,
        'added_date': '2026-10-13T17:00:00', 'duration': 900}})
    monkeypatch.setattr(sys, 'argv', ['aiwaf', '--data-dir', str(tmp_path), 'list', 'blacklist'])
    cli.main()
    output = capsys.readouterr().out
    assert '2026-10-13T17:00:00' in output
    assert '(Unknown)' not in output


def test_default_blocks_remain_active_at_one_minute(tmp_path):
    app = Flask(__name__)
    app.config.update(AIWAF_USE_CSV=True, AIWAF_DATA_DIR=str(tmp_path))
    with app.app_context():
        storage.add_ip_blacklist('203.0.113.1', 'Excessive 404s')
        entry = policy.read_blacklist(tmp_path)['203.0.113.1']
        assert entry['duration'] == 900
        assert entry['expires_at'] - entry['blocked_at'] == 900
        assert policy.native_check_blacklist(Path(tmp_path), '203.0.113.1', entry['blocked_at'] + 60)
        assert policy.native_check_blacklist(Path(tmp_path), '203.0.113.1', entry['blocked_at'] + 899)
        assert not policy.native_check_blacklist(Path(tmp_path), '203.0.113.1', entry['blocked_at'] + 900)
