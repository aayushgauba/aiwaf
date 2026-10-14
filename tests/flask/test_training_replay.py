import time
import pytest
from flask import Flask
from aiwaf.flask import trainer, storage
from tests.training_replay_helpers import write_logs


@pytest.mark.parametrize('removal', ['manual', 'expiry'])
def test_training_requires_six_fresh_404s_after_unblock(tmp_path, monkeypatch, removal):
    logs = tmp_path / 'logs'
    logs.mkdir()
    file = logs / 'access.log'
    write_logs(file, 60)
    app = Flask(__name__)
    app.config.update(AIWAF_USE_CSV=True, AIWAF_DATA_DIR=str(tmp_path / 'data'),
                      AIWAF_LOG_DIR=str(logs), AIWAF_EXEMPT_PATHS=[])
    monkeypatch.setattr(trainer, '_print_geoip_blocklist_summary', lambda: None)
    with app.app_context():
        trainer.FlaskAITrainer(app).train(disable_ai=True)
        before = storage._read_csv_blocklist()
        assert '203.0.113.1' in before
        trainer.FlaskAITrainer(app).train(disable_ai=True)
        assert storage._read_csv_blocklist() == before
        if removal == 'manual':
            storage.remove_ip_blocklist('203.0.113.1')
        else:
            before['203.0.113.1']['expires_at'] = time.time() - 1
            storage._rewrite_csv_blocklist(before)
            assert not storage.is_ip_blocklisted('203.0.113.1')
        trainer.FlaskAITrainer(app).train(disable_ai=True)
        assert storage._read_csv_blocklist() == {}
        write_logs(file, 65)
        trainer.FlaskAITrainer(app).train(disable_ai=True)
        assert storage._read_csv_blocklist() == {}
        write_logs(file, 66)
        trainer.FlaskAITrainer(app).train(disable_ai=True)
        assert '203.0.113.1' in storage._read_csv_blocklist()


def test_ai_enforcement_does_not_mix_old_anomalies_with_one_benign_request(tmp_path, monkeypatch):
    app = Flask(__name__)
    app.config.update(AIWAF_USE_CSV=True, AIWAF_DATA_DIR=str(tmp_path / 'data'),
                      AIWAF_MODEL_PATH=str(tmp_path / 'model.json'), AIWAF_FORCE_AI=True)
    instance = trainer.FlaskAITrainer(app)
    lines = ['203.0.113.1 - - [10/Oct/2026:12:00:00 +0000] "GET /docs HTTP/1.1" 200 207\n'] * 60
    monkeypatch.setattr(instance, '_read_all_logs', lambda: lines)
    monkeypatch.setattr(trainer, '_print_geoip_blocklist_summary', lambda: None)
    monkeypatch.setattr(trainer, 'AI_AVAILABLE', False)
    def features(parsed, errors, times):
        fresh = len(parsed) == 1
        return [dict(ip=row['ip'], kw_hits=0 if fresh else 2,
                     total_404=0 if fresh else 10, burst_count=1) for row in parsed]
    monkeypatch.setattr(instance, '_generate_feature_dicts', features)
    fitted, scored = [], []
    class Forest:
        def __init__(self, **kwargs):
            pass
        def fit(self, values):
            fitted.append(len(values))
        def predict(self, values):
            scored.append(len(values))
            return [-1] * len(values)
        def to_json(self):
            return '{}'
    monkeypatch.setattr(trainer, 'get_isolation_forest_class', lambda: Forest)
    with app.app_context():
        instance.train()
        assert storage.is_ip_blocklisted('203.0.113.1')
        storage.remove_ip_blocklist('203.0.113.1')
        lines.append('203.0.113.1 - - [10/Oct/2026:12:01:00 +0000] "GET /docs HTTP/1.1" 200 207\n')
        instance.train()
        assert not storage.is_ip_blocklisted('203.0.113.1')
    assert fitted == [60, 61]
    assert scored[-1] == 1
