import csv
import json
import time

import pytest

from aiwaf.core import storage_csv_impl as policy
from aiwaf.core.runtime_storage import (
    initialize_storage, get_blocklist_store, get_exemption_store, get_keyword_store, get_geo_block_store,
)
from aiwaf.core.policy_csv_storage import PolicyCSVStorage
from aiwaf.core.native_runtime import native_override


def legacy_file(path, values):
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open('w', newline='', encoding='utf-8') as stream:
        writer = csv.writer(stream)
        writer.writerow(['key', 'value', 'expires_at'])
        for key, value, expiry in values:
            writer.writerow([key, json.dumps(value), expiry or ''])


@pytest.mark.parametrize('native', [False, True])
def test_migration_preserves_policy_metadata_expiry_and_does_not_replay(tmp_path, native):
    source = tmp_path / 'runtime_store.csv'
    expiry = time.time() + 600
    block = dict(ip='203.0.113.1', reason='scan', reputation_reason='repeat', reasons=['scan'],
                 score=42, offenses=3, blocked_at=time.time() - 10, expires_at=expiry + 100,
                 duration=710, permanent=False, extended_request_info={'path': '/wp.php'})
    legacy_file(source, [
        ('blocked:203.0.113.1', block, expiry),
        ('blocked:203.0.113.2', 'old permanent block', None),
        ('blocked:203.0.113.3', block, time.time() - 1),
        ('exemptions', {'ips': ['192.0.2.1'], 'patterns': ['198.51.100.*']}, None),
        ('keyword_counts', {'scanner': 15}, None),
        ('geo_blocked_countries', ['CN'], None),
        ('path_exemptions', {'/monitor': 'health check'}, None),
        ('custom:history', {'preserved': True}, expiry),
    ])
    original = source.read_bytes()
    with native_override(native):
        store = initialize_storage('csv', data_dir=tmp_path)
        info = get_blocklist_store().get_block_info('203.0.113.1')
        assert info['expires_at'] == expiry
        for key in ('reason', 'reputation_reason', 'reasons', 'score', 'offenses', 'duration', 'extended_request_info'):
            assert info[key] == block[key]
        assert get_blocklist_store().get_block_info('203.0.113.2')['permanent']
        assert not get_blocklist_store().is_blocked('203.0.113.3')
        assert get_exemption_store().is_exempted('198.51.100.10')
        assert get_keyword_store().get_all_keywords() == ['scanner']
        assert store.get('keyword_counts') == {'scanner': 15}
        assert get_geo_block_store().get_countries() == {'CN'}
        assert policy.read_path_exemptions(tmp_path) == {'/monitor': 'health check'}
        assert store.get('custom:history') == {'preserved': True}
        assert source.read_bytes() == original
        get_blocklist_store().unblock_ip('203.0.113.1')
        get_keyword_store().remove_keyword('scanner')
        get_exemption_store().remove_pattern('198.51.100.*')
        store = initialize_storage('csv', data_dir=tmp_path)
        assert not get_blocklist_store().is_blocked('203.0.113.1')
        assert get_keyword_store().get_all_keywords() == []
        assert not get_exemption_store().is_exempted('198.51.100.10')
        assert source.read_bytes() == original


@pytest.mark.parametrize('native', [False, True])
def test_canonical_policy_changes_are_visible_both_directions(tmp_path, native):
    with native_override(native):
        store = initialize_storage('csv', data_dir=tmp_path)
        get_blocklist_store().block_ip('203.0.113.5', 'probe', duration=60)
        assert policy.read_blocklist(tmp_path)['203.0.113.5']['reason'] == 'probe'
        assert get_blocklist_store().get_block_stats()['total_blocks_all_time'] == 1
        policy.native_remove_blocklist(tmp_path, '203.0.113.5') if native else policy.rewrite_blocklist(tmp_path, {})
        assert not get_blocklist_store().is_blocked('203.0.113.5')
        get_exemption_store().add_ip('192.0.2.8')
        assert '192.0.2.8' in policy.read_allowlist(tmp_path)
        policy.append_allowlist(tmp_path, '192.0.2.9')
        assert get_exemption_store().is_exempted('192.0.2.9')
        get_keyword_store().add_keyword('scan', 4)
        assert policy.read_keywords(tmp_path) == {'scan'}
        policy.append_keyword(tmp_path, 'external')
        assert store.get('keyword_counts') == {'scan': 4, 'external': 1}
        policy.rewrite_keywords(tmp_path, {'external'})
        assert get_keyword_store().get_all_keywords() == ['external']
        get_geo_block_store().add_country('CN')
        assert policy.read_geo_blocked_countries(tmp_path) == {'CN'}
        policy.rewrite_geo_blocked_countries(tmp_path, {'US'})
        assert get_geo_block_store().get_countries() == {'US'}


def test_conflicts_keep_canonical_policy_and_migration_is_recoverable(tmp_path, monkeypatch):
    existing = PolicyCSVStorage(data_dir=tmp_path)
    existing.set('blocked:203.0.113.1', {'reason': 'canonical', 'permanent': True})
    source = tmp_path / 'runtime_store.csv'
    legacy_file(source, [('blocked:203.0.113.1', 'older', None), ('keyword_counts', {'scanner': 9}, None)])
    real_set = PolicyCSVStorage._set
    def fail(self, key, value, ttl=None):
        if key == 'keyword_counts':
            raise OSError('simulated disk failure')
        return real_set(self, key, value, ttl)
    with monkeypatch.context() as patch:
        patch.setattr(PolicyCSVStorage, '_set', fail)
        with pytest.raises(OSError, match='disk failure'):
            PolicyCSVStorage(data_dir=tmp_path)
    recovered = PolicyCSVStorage(data_dir=tmp_path)
    assert recovered.get('blocked:203.0.113.1')['reason'] == 'canonical'
    assert recovered.get('keyword_counts') == {'scanner': 9}
    assert list(tmp_path.glob('.csv-backup-*'))


@pytest.mark.parametrize('rows', [
    'unexpected,header\na,b\n',
    'key,value,expires_at\nexemptions,42,\n',
    'key,value,expires_at\nkeyword_counts,"{""a"":""bad""}",\n',
    'key,value,expires_at\nblocked:1,"""block""",nan\n',
])
def test_malformed_legacy_input_fails_startup_without_import(tmp_path, rows):
    source = tmp_path / 'runtime_store.csv'
    source.write_text(rows)
    with pytest.raises(ValueError):
        PolicyCSVStorage(data_dir=tmp_path)
    assert not list(tmp_path.glob('.csv-migration-*.json'))
    assert source.read_text() == rows


def test_legacy_custom_files_keep_isolated_policy_directories(tmp_path):
    first = initialize_storage('csv', file_path=tmp_path / 'first.csv')
    first.set('blocked:203.0.113.1', 'first')
    second = initialize_storage('csv', file_path=tmp_path / 'second.csv')
    assert second.get('blocked:203.0.113.1') is None
    assert first.data_dir != second.data_dir


def test_unicode_policy_survives_python_to_rust_switch(tmp_path):
    with native_override(False):
        initialize_storage('csv', data_dir=tmp_path)
        get_blocklist_store().block_ip('203.0.113.99', 'Requests ≥ 60; café', duration=60)
        get_keyword_store().add_keyword('scannér', 4)
    with native_override(True):
        store = initialize_storage('csv', data_dir=tmp_path)
        assert get_blocklist_store().get_block_info('203.0.113.99')['reason'] == 'Requests ≥ 60; café'
        assert store.get('keyword_counts') == {'scannér': 4}


def test_old_default_csv_is_discovered_and_cli_reuses_destination(tmp_path, monkeypatch):
    from aiwaf.flask.cli import AIWAFManager
    from aiwaf.flask import auto_config
    monkeypatch.chdir(tmp_path)
    monkeypatch.delenv('AIWAF_DATA_DIR', raising=False)
    monkeypatch.setattr(auto_config, '_auto_config', None)
    source = tmp_path / 'aiwaf_data.csv'
    legacy_file(source, [('blocked:203.0.113.12', 'legacy default', None)])
    original = source.read_bytes()
    manager = AIWAFManager()
    assert manager.policy_storage.data_dir == tmp_path / 'aiwaf_data'
    assert '203.0.113.12' in manager.storage['read_blocklist']()
    assert source.read_bytes() == original
