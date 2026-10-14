"""FastAPI trainer integration, native parity, and CLI regression tests."""
import csv
import sys
from types import SimpleNamespace
import pytest
from fastapi import FastAPI
from aiwaf.core import rust_backend
from aiwaf.core.runtime_config import AIWAFConfig
from aiwaf.core.runtime_storage import initialize_storage, get_keyword_store, get_blocklist_store, get_storage, get_exemption_store
from aiwaf.fast.trainer import train_from_logs, path_exists


def make_log(root):
    root.mkdir()
    with (root / 'access.log').open('w', newline='', encoding='utf-8') as file:
        writer = csv.writer(file)
        writer.writerow(['timestamp', 'ip', 'method', 'path', 'status_code', 'response_time_ms'])
        for i in range(90):
            writer.writerow(['2026-10-10T12:00:00', f'203.0.113.{i % 3 + 1}', 'GET',
                '/wp-content/customplugin/shell.php' if i % 3 else '/users/123', '404', '125'])


def test_fast_training_uses_runtime_csv_and_native_parity(tmp_path, monkeypatch):
    module = pytest.importorskip('aiwaf_rust')
    monkeypatch.setattr(rust_backend, 'aiwaf_rust', module)
    make_log(tmp_path / 'logs')
    app = FastAPI()
    app.add_api_route('/users/{user_id}', lambda user_id: {'ok': True})
    states = []
    for native in [False, True]:
        cfg = AIWAFConfig(load_from_env=False)
        cfg.set('AIWAF_USE_RUST', native)
        cfg.set('AIWAF_EXEMPT_PATHS', [])
        initialize_storage('csv', file_path=str(tmp_path / f'{native}.csv'))
        result = train_from_logs(app, log_dir=tmp_path / 'logs', disable_ai=True, config=cfg)
        assert result['parsed_records'] == 90
        assert result['blocked_404'] == 3
        assert 'customplugin' in result['learned_keywords']
        assert 'users' not in result['learned_keywords']
        states.append((set(get_blocklist_store().get_blocked_ips()), get_storage().get('keyword_counts')))
    assert states[0] == states[1]


def test_fast_route_matching_mounts_and_methods():
    app, child = FastAPI(), FastAPI()
    child.add_api_route('/users/{user_id}', lambda: {}, methods=['POST'])
    app.mount('/api', child)
    assert path_exists(app, '/api/users/123?x=1')
    assert not path_exists(app, '/api/nonexistent')


def test_fast_training_honors_ip_exemptions_and_trains_model(tmp_path, monkeypatch):
    module = pytest.importorskip('aiwaf_rust')
    monkeypatch.setattr(rust_backend, 'aiwaf_rust', module)
    make_log(tmp_path / 'logs')
    initialize_storage('csv', file_path=str(tmp_path / 'runtime.csv'))
    get_exemption_store().add_ip('203.0.113.2')
    result = train_from_logs(FastAPI(), log_dir=tmp_path / 'logs', force_ai=True,
                             model_path=tmp_path / 'model.json')
    assert not get_blocklist_store().is_blocked('203.0.113.2')
    assert result['model'] is not None
    assert (tmp_path / 'model.json').exists()


def test_fast_cli_train_avoids_flask_fallback(tmp_path, monkeypatch, capsys):
    from aiwaf.fast import cli, trainer
    monkeypatch.setattr(cli, '_load_fastapi_app', lambda value: FastAPI())
    monkeypatch.setattr(cli, '_flask_cli_main', lambda: pytest.fail('Flask training fallback'))
    monkeypatch.setattr(trainer, 'train_from_logs', lambda *args, **kwargs: {'parsed_records': 50, 'model': None})
    monkeypatch.setattr(sys, 'argv', ['aiwaf-fast', '--data-dir', str(tmp_path), 'train', '--app', 'sample:app', '--disable-ai'])
    cli.main()
    assert '50' in capsys.readouterr().out
    assert get_storage().data_dir == tmp_path
    assert get_storage().file_path == tmp_path / 'runtime_metadata.csv'
