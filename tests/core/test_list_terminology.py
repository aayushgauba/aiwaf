"""Naming changes retain existing imports, settings and persisted policy data."""
import importlib


def test_previous_modules_and_symbols_share_implementations():
    for old, new in [('core.runtime_blacklist', 'core.runtime_blocklist'),
                     ('core.blacklist', 'core.blocklist'),
                     ('core.blacklist_migration', 'core.blocklist_migration'),
                     ('flask.blacklist_manager', 'flask.blocklist_manager'),
                     ('fast.blacklist', 'fast.blocklist')]:
        assert importlib.import_module('aiwaf.' + old) is importlib.import_module('aiwaf.' + new)
    from aiwaf.core.runtime_blocklist import BlocklistManager, BlacklistManager
    assert BlacklistManager is BlocklistManager
    assert BlocklistManager.__dict__['add_to_whitelist'] is BlocklistManager.__dict__['add_to_allowlist']


def test_native_exports_support_previous_names():
    import aiwaf_rust
    assert aiwaf_rust.csv_blacklist_check is aiwaf_rust.csv_blocklist_check
    assert aiwaf_rust.csv_blacklist_block is aiwaf_rust.csv_blocklist_block


def test_existing_policy_files_keep_blocks_and_exemptions(tmp_path):
    from aiwaf.core.storage_csv_impl import ensure_all, read_blocklist, read_allowlist
    (tmp_path/'blacklist.csv').write_text('ip,reason\n8.8.8.8,existing block\n', encoding='utf-8')
    (tmp_path/'whitelist.csv').write_text('ip,added_date\n9.9.9.9,2026-10-14\n', encoding='utf-8')
    ensure_all(tmp_path)
    assert '8.8.8.8' in read_blocklist(tmp_path)
    assert '9.9.9.9' in read_allowlist(tmp_path)


def test_old_configuration_names_and_new_name_precedence(monkeypatch):
    from aiwaf.core.runtime_config import AIWAFConfig
    monkeypatch.setenv('AIWAF_BLACKLIST_DEFAULT_DURATION', '1200')
    cfg = AIWAFConfig()
    assert cfg.get('blocklist.default_block_duration') == 1200
    assert cfg.get('blacklist.default_block_duration') == 1200
    monkeypatch.setenv('AIWAF_BLOCKLIST_DEFAULT_DURATION', '1800')
    assert AIWAFConfig().get('blocklist.default_block_duration') == 1800
    cfg.update({'blacklist': {'default_block_duration': 600}, 'blocklist': {'default_block_duration': 900}})
    assert cfg.get('blocklist.default_block_duration') == 900


def test_cli_accepts_previous_names_with_explicit_data_directory(monkeypatch, capsys, tmp_path):
    import sys
    from types import SimpleNamespace
    from aiwaf.flask import cli
    manager = SimpleNamespace(list_allowlist=lambda: [], list_blocklist=lambda: {})
    monkeypatch.setattr(cli, 'AIWAFManager', lambda directory: manager)
    for name in ('allowlist', 'whitelist', 'blocklist', 'blacklist'):
        monkeypatch.setattr(sys, 'argv', ['aiwaf', '--data-dir', str(tmp_path), 'list', name])
        cli.main()
        assert '(0)' in capsys.readouterr().out
