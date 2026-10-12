import csv
from flask import Flask
import pytest
from aiwaf.core import rust_backend
from aiwaf.flask import trainer, storage


def test_csv_access_log_training_parity(tmp_path, monkeypatch):
    native = pytest.importorskip('aiwaf_rust')
    monkeypatch.setattr(rust_backend, 'aiwaf_rust', native)
    monkeypatch.setattr(trainer, '_print_geoip_blocklist_summary', lambda: None)
    results = []
    for mode in [False, True]:
        root = tmp_path / str(mode)
        logs = root / 'logs'
        logs.mkdir(parents=True)
        with (logs / 'access.log').open('w', newline='', encoding='utf-8') as file:
            writer = csv.writer(file)
            writer.writerow(['timestamp', 'ip', 'method', 'path', 'status_code', 'response_time_ms'])
            for i in range(60):
                writer.writerow(['2026-10-10T12:00:00', f'203.0.113.{i % 3 + 1}', 'GET',
                                 '/wp-content/customplugin/shell.php', '404', '125'])
        app = Flask(__name__)
        app.config.update(AIWAF_DATA_DIR=str(root / 'data'), AIWAF_LOG_DIR=str(logs),
                          AIWAF_RUST_CSV=mode, AIWAF_USE_RUST=True, AIWAF_EXEMPT_PATHS=[])
        with app.app_context():
            trainer.FlaskAITrainer(app).train(disable_ai=True)
            blacklist = storage._read_csv_blacklist()
            keywords = storage._read_csv_keywords()
            assert len(blacklist) == 3
            assert 'customplugin' in keywords
            results.append((set(blacklist), keywords))
    assert results[0] == results[1]


def test_rust_model_list_predictions_block_without_dataframe(tmp_path, monkeypatch):
    native = pytest.importorskip('aiwaf_rust')
    monkeypatch.setattr(rust_backend, 'aiwaf_rust', native)
    app = Flask(__name__)
    app.config.update(AIWAF_DATA_DIR=str(tmp_path / 'data'), AIWAF_FORCE_AI=True,
                      AIWAF_MODEL_PATH=str(tmp_path / 'model.json'), AIWAF_EXEMPT_PATHS=[])
    instance = trainer.FlaskAITrainer(app)
    lines = ['203.0.113.1 - - [10/Oct/2026:12:00:00 +0000] "GET /docs HTTP/1.1" 200 207\n'] * 60
    monkeypatch.setattr(instance, '_read_all_logs', lambda: lines)
    features = [dict(ip='203.0.113.1', kw_hits=2, total_404=10, burst_count=1)] * 60
    monkeypatch.setattr(instance, '_generate_feature_dicts', lambda *args: features)
    monkeypatch.setattr(trainer, 'AI_AVAILABLE', False)
    monkeypatch.setattr(trainer, '_print_geoip_blocklist_summary', lambda: None)
    class NoDataFrame:
        def DataFrame(self, *args):
            raise AssertionError('Rust model path must not construct a DataFrame')
    monkeypatch.setattr(trainer, 'pd', NoDataFrame())
    calls = []
    class Forest:
        def __init__(self, **kwargs):
            pass
        def fit(self, values):
            assert isinstance(values, list) and len(values) == 60
            calls.append('fit')
        def predict(self, values):
            return [-1] + [1] * 59
        def to_json(self):
            return '{}'
    monkeypatch.setattr(trainer, 'get_isolation_forest_class', lambda: Forest)
    with app.app_context():
        instance.train(disable_ai=False)
        assert calls == ['fit']
        assert '203.0.113.1' in storage._read_csv_blacklist()
        assert (tmp_path / 'model.json').exists()


def test_real_native_feature_handle_saves_model(tmp_path, monkeypatch):
    native = pytest.importorskip('aiwaf_rust')
    monkeypatch.setattr(rust_backend, 'aiwaf_rust', native)
    monkeypatch.setattr(trainer, '_print_geoip_blocklist_summary', lambda: None)
    logs = tmp_path / 'logs'
    logs.mkdir()
    with (logs / 'access.log').open('w', newline='', encoding='utf-8') as file:
        writer = csv.writer(file)
        writer.writerow(['timestamp', 'ip', 'path', 'status_code', 'response_time_ms'])
        for i in range(60):
            writer.writerow(['2026-10-10T12:00:00', '203.0.113.1', '/wp-content/shell.php', '404', str(i)])
    app = Flask(__name__)
    app.config.update(AIWAF_USE_CSV=True, AIWAF_USE_RUST=True, AIWAF_FORCE_AI=True,
        AIWAF_DATA_DIR=str(tmp_path / 'data'), AIWAF_LOG_DIR=str(logs), AIWAF_MODEL_PATH=str(tmp_path / 'model.json'))
    with app.app_context():
        trainer.FlaskAITrainer(app).train()
    from aiwaf.core.model_serialization import load_model_artifact
    artifact = load_model_artifact(tmp_path / 'model.json')
    assert artifact['samples_count'] == 60
    assert artifact['feature_count'] == 6
    assert artifact['backend'] == 'rust'
