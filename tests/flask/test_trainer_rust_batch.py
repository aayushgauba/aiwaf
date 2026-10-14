from datetime import datetime, timedelta
from collections import defaultdict

from flask import Flask

from aiwaf.flask import trainer


class _DummyKeywordStore:
    def add_keyword(self, kw, cnt):
        return None


def _build_app():
    app = Flask(__name__)
    app.config.update(
        {
            "TESTING": True,
            "AIWAF_USE_RUST": True,
            "AIWAF_RUST_FEATURE_BATCH_SIZE": 2,
            "AIWAF_MIN_AI_LOGS": 10_000,
            "AIWAF_FORCE_AI": False,
        }
    )
    return app


def _fake_record(i):
    return {
        "ip": f"10.0.0.{(i % 5) + 1}",
        "path": f"/wp-admin/{i}",
        "status": "404",
        "timestamp": datetime(2026, 1, 1) + timedelta(seconds=i),
        "response_time": 0.1,
    }


def test_trainer_uses_chunked_rust_extraction(monkeypatch):
    app = _build_app()
    t = trainer.FlaskAITrainer(app)

    monkeypatch.setattr(trainer.FlaskAITrainer, "remove_exempt_keywords", lambda self: None)
    monkeypatch.setattr(trainer.FlaskAITrainer, "_read_all_logs", lambda self: [f"line-{i}" for i in range(50)])
    monkeypatch.setattr(trainer.FlaskAITrainer, "_parse", lambda self, line: _fake_record(int(line.split("-")[-1])))
    monkeypatch.setattr(trainer.FlaskAITrainer, "path_exists_in_flask", lambda self, path: False)
    monkeypatch.setattr(trainer, "is_path_exempt", lambda path: False)
    monkeypatch.setattr(trainer, "get_keyword_store", lambda: _DummyKeywordStore())
    monkeypatch.setattr(trainer, "_print_geoip_blocklist_summary", lambda: None)
    monkeypatch.setattr(trainer.BlocklistManager, "block", lambda ip, reason: None)
    monkeypatch.setattr(trainer, "rust_available", lambda: True)
    monkeypatch.setattr(trainer, "rust_supports_chunked_features", lambda: True)
    monkeypatch.setattr(trainer, "core_extract_raw_features", lambda *args: None)

    calls = {"batch": [], "finalize": [], "plain_extract": 0}

    def _batch(records, static_keywords, state):
        calls["batch"].append((records, static_keywords, state))
        next_state = {"chunks": 1 if state is None else state["chunks"] + 1}
        return [{"ip": r["ip"], "path_len": r["path_len"], "kw_hits": 1, "resp_time": 0.1, "status_idx": 2, "burst_count": 1, "total_404": r["total_404"]} for r in records], next_state

    def _finalize(static_keywords, state):
        calls["finalize"].append((static_keywords, state))
        return []

    monkeypatch.setattr(trainer, "rust_extract_features_batch", _batch)
    monkeypatch.setattr(trainer, "rust_finalize_feature_state", _finalize)
    monkeypatch.setattr(trainer, "rust_extract_features", lambda *args, **kwargs: calls.__setitem__("plain_extract", calls["plain_extract"] + 1))

    with app.app_context():
        t.train(disable_ai=True)

    assert len(calls["batch"]) == 25
    assert all(len(chunk_records) <= 2 for chunk_records, _, _ in calls["batch"])
    assert len(calls["finalize"]) == 1
    assert calls["plain_extract"] == 0


def test_generate_feature_dicts_prefers_raw_rust_batch(monkeypatch):
    app = _build_app()
    trainer_instance = trainer.FlaskAITrainer(app)
    expected = [{"ip": "203.0.113.1", "kw_hits": 1}]
    monkeypatch.setattr(trainer, "rust_available", lambda: True)
    monkeypatch.setattr(trainer, "core_extract_raw_features", lambda *args: expected)

    def _unexpected_old_path(*args):
        raise AssertionError("old record preparation should be skipped")

    monkeypatch.setattr(trainer, "core_build_records", _unexpected_old_path)
    with app.app_context():
        result = trainer_instance._generate_feature_dicts(
            [_fake_record(0)], {"10.0.0.1": 1}, {}
        )
    assert result == expected


def test_trainer_falls_back_to_python_features_when_chunked_batch_fails(monkeypatch):
    app = _build_app()
    t = trainer.FlaskAITrainer(app)

    monkeypatch.setattr(trainer.FlaskAITrainer, "remove_exempt_keywords", lambda self: None)
    monkeypatch.setattr(trainer.FlaskAITrainer, "_read_all_logs", lambda self: [f"line-{i}" for i in range(50)])
    monkeypatch.setattr(trainer.FlaskAITrainer, "_parse", lambda self, line: _fake_record(int(line.split("-")[-1])))
    monkeypatch.setattr(trainer.FlaskAITrainer, "path_exists_in_flask", lambda self, path: False)
    monkeypatch.setattr(trainer, "is_path_exempt", lambda path: False)
    monkeypatch.setattr(trainer, "get_keyword_store", lambda: _DummyKeywordStore())
    monkeypatch.setattr(trainer, "_print_geoip_blocklist_summary", lambda: None)
    monkeypatch.setattr(trainer.BlocklistManager, "block", lambda ip, reason: None)
    monkeypatch.setattr(trainer, "rust_available", lambda: True)
    monkeypatch.setattr(trainer, "rust_supports_chunked_features", lambda: True)
    monkeypatch.setattr(trainer, "core_extract_raw_features", lambda *args: None)
    monkeypatch.setattr(
        trainer,
        "rust_extract_features_batch",
        lambda records, static_keywords, state: (None, state),
    )

    finalize_calls = {"count": 0}

    def _finalize(static_keywords, state):
        finalize_calls["count"] += 1
        return []

    monkeypatch.setattr(trainer, "rust_finalize_feature_state", _finalize)

    with app.app_context():
        t.train(disable_ai=True)

    # Django-style streaming always finalizes state, even if a batch returns no features.
    assert finalize_calls["count"] == 1


def test_generate_feature_dicts_python_parallel_with_caching(monkeypatch):
    app = _build_app()
    t = trainer.FlaskAITrainer(app)

    monkeypatch.setattr(trainer, "rust_available", lambda: False)

    calls = {"path_exists": 0, "is_exempt": 0}

    def _path_exists(self, path):
        calls["path_exists"] += 1
        return False

    def _is_exempt(path):
        calls["is_exempt"] += 1
        return False

    monkeypatch.setattr(trainer.FlaskAITrainer, "path_exists_in_flask", _path_exists)
    monkeypatch.setattr(trainer, "is_path_exempt", _is_exempt)

    monkeypatch.setenv("AIWAF_PYTHON_PARALLEL_FEATURES", "1")
    monkeypatch.setenv("AIWAF_PYTHON_PARALLEL_CHUNK_SIZE", "4")
    monkeypatch.setenv("AIWAF_PYTHON_PARALLEL_WORKERS", "2")
    monkeypatch.setenv("AIWAF_PYTHON_FEATURE_BATCH_SIZE", "3")

    parsed = []
    ip_404 = defaultdict(int)
    ip_times = defaultdict(list)
    for i in range(50):
        rec = _fake_record(i % 10)
        parsed.append(rec)
        ip_404[rec["ip"]] += 1
        ip_times[rec["ip"]].append(rec["timestamp"])

    with app.app_context():
        features = t._generate_feature_dicts(parsed, ip_404, ip_times)

    assert len(features) == 50
    # Repeated paths should be cached; only unique fake paths should be looked up.
    assert calls["path_exists"] == 10
    assert calls["is_exempt"] == 10
