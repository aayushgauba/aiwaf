from aiwaf.flask import trainer


def test_geoip_summary_for_blocklist(capsys, monkeypatch):
    monkeypatch.setattr(trainer, "_get_storage_mode", lambda: "csv")
    monkeypatch.setattr(trainer, "_read_csv_blocklist", lambda: {"1.1.1.1": "test", "2.2.2.2": "test"})
    monkeypatch.setattr(trainer, "lookup_country_name", lambda ip, **kwargs: "United States" if ip == "1.1.1.1" else None)
    monkeypatch.setattr(trainer.os.path, "exists", lambda path: True)
    monkeypatch.setattr(trainer, "_get_geoip_db_path", lambda: "fake.mmdb")

    trainer._print_geoip_blocklist_summary()

    out = capsys.readouterr().out
    assert "GeoIP summary for blocked IPs" in out
    assert "United States: 1" in out
    assert "UNKNOWN: 1" in out


def test_geoip_summary_skips_missing_db(capsys, monkeypatch):
    monkeypatch.setattr(trainer, "_get_storage_mode", lambda: "csv")
    monkeypatch.setattr(trainer, "_read_csv_blocklist", lambda: {"1.1.1.1": "test"})
    monkeypatch.setattr(trainer.os.path, "exists", lambda path: False)
    monkeypatch.setattr(trainer, "_get_geoip_db_path", lambda: "missing.mmdb")

    trainer._print_geoip_blocklist_summary()

    out = capsys.readouterr().out
    assert "GeoIP summary skipped" in out
import json
from flask import Flask


def test_trainer_log_adapters_routes_and_compatibility_helpers(tmp_path, monkeypatch):
    from aiwaf.flask import trainer

    app = Flask(__name__)
    app.config["AIWAF_LOG_DIR"] = str(tmp_path)
    app.add_url_rule("/health", "health", lambda: "ok")
    instance = trainer.FlaskAITrainer(app)
    assert instance.path_exists_in_flask("/health")
    assert not instance.path_exists_in_flask("/missing")

    csv_path = tmp_path / "access.csv"
    csv_path.write_text(
        "timestamp,ip,method,path,status_code,response_time_ms,user_agent,referer\n"
        "30/Aug/2026:12:00:00,203.0.113.1,GET,/health,200,10,pytest,-\n",
        encoding="utf-8",
    )
    assert len(instance._get_logs_from_csv()) == 1
    csv_path.unlink()
    json_path = tmp_path / "access.jsonl"
    json_path.write_text(
        json.dumps({"timestamp": "30/Aug/2026:12:00:00", "ip": "203.0.113.1", "method": "GET", "path": "/health", "status_code": 200}) + "\n",
        encoding="utf-8",
    )
    lines = instance._get_logs_from_json()
    assert len(lines) == 1
    assert instance._parse(lines[0]) is not None
    assert not instance._is_malicious_context_trainer("/health", "health", "200")
    assert "health" in instance.get_legitimate_keywords()

    trainer.init_trainer(app)
    assert "health" in trainer.get_legitimate_keywords()
    with app.app_context():
        assert trainer._get_geoip_db_path()
    assert trainer._extract_rust_features_parallel([], [], 1, 1) == []

    calls = []
    monkeypatch.setattr(trainer._trainer, "train", lambda disable_ai=False: calls.append(disable_ai))
    trainer.train(disable_ai=True)
    assert calls == [True]
