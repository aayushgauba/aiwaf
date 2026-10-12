import pytest
from django.test import override_settings
from aiwaf.core import rust_backend

pytestmark = pytest.mark.django


def test_streaming_csv_training_native_and_python_parity(tmp_path, monkeypatch):
    from aiwaf.django import trainer, storage
    from aiwaf.core.runtime_storage import get_storage
    native = pytest.importorskip('aiwaf_rust')
    monkeypatch.setattr(rust_backend, 'aiwaf_rust', native)
    lines = [f'203.0.113.{i % 3 + 1} - - [10/Oct/2026:12:00:00 +0000] "GET /wp-content/customplugin/shell.php HTTP/1.1" 404 207 "-" "pytest" response-time=0.125\n' for i in range(4200)]
    monkeypatch.setattr(trainer, '_iter_all_logs', lambda: iter(lines))
    monkeypatch.setattr(trainer, '_print_geoip_summary', lambda *args: None)
    monkeypatch.setattr(trainer, '_print_geoip_blocklist_summary', lambda: None)
    monkeypatch.setattr(trainer, 'get_legitimate_keywords', lambda: set())
    states = []
    for mode in [False, True]:
        with override_settings(AIWAF_STORAGE_MODE='csv', AIWAF_DATA_DIR=str(tmp_path / str(mode)),
            AIWAF_USE_RUST=True, AIWAF_RUST_CSV=mode, AIWAF_EXEMPT_PATHS=[], AIWAF_EXEMPT_KEYWORDS=[]):
            trainer.train(disable_ai=True)
            store = storage.get_keyword_store()
            assert 'customplugin' in store.get_all_keywords()
            counts = get_storage().get('keyword_counts')
            assert counts['customplugin'] == 4200
            states.append((set(storage.get_blacklist_store().get_all_blocked_ips()), counts))
    assert states[0] == states[1]


def test_csv_adapter_bulk_counts(tmp_path):
    from aiwaf.django.storage import get_keyword_store
    with override_settings(AIWAF_STORAGE_MODE='csv', AIWAF_DATA_DIR=str(tmp_path)):
        store = get_keyword_store()
        store.update_keywords(added=[('shelltest', 5), ('remove', 2)])
        store.update_keywords(added=[('shelltest', 3)], removed={'remove'})
        assert store.get_all_keywords() == ['shelltest']


def test_direct_csv_stream_and_opaque_model_fit(tmp_path, monkeypatch):
    import csv
    from aiwaf.django import trainer
    native = pytest.importorskip('aiwaf_rust')
    monkeypatch.setattr(rust_backend, 'aiwaf_rust', native)
    file = tmp_path / 'access.csv'
    with file.open('w', newline='', encoding='utf-8') as stream:
        writer = csv.writer(stream)
        writer.writerow(['timestamp', 'ip', 'path', 'status_code', 'response_time'])
        for i in range(60):
            writer.writerow(['2026-10-10T12:00:00.123456+05:30', '203.0.113.1', '/wp-content/shell.php', '404', str(i / 1000)])
    monkeypatch.setattr(trainer, 'LOG_PATH', str(file))
    monkeypatch.setattr(trainer, '_print_geoip_summary', lambda *args: None)
    monkeypatch.setattr(trainer, '_print_geoip_blocklist_summary', lambda: None)
    artifacts = []
    monkeypatch.setattr(trainer, 'save_model_data', lambda data, **kwargs: artifacts.append(data) or True)
    with override_settings(AIWAF_STORAGE_MODE='csv', AIWAF_DATA_DIR=str(tmp_path / 'data'),
        AIWAF_USE_RUST=True, AIWAF_RUST_CSV=True, AIWAF_RUST_FEATURE_CHUNK_SIZE=13):
        trainer.train(force_ai=True)
    assert len(artifacts) == 1
    assert artifacts[0]['samples_count'] == 60
    assert artifacts[0]['feature_count'] == 6
    assert artifacts[0]['backend'] == 'rust'
