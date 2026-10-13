"""Differential policy, persistence and concurrency checks for the native chain."""
import csv
import json
from concurrent.futures import ThreadPoolExecutor
import pytest
from aiwaf.core import header_validation
from aiwaf.core.sql_injection import SQLInjectionPolicy

rust = pytest.importorskip("aiwaf_rust")
pytestmark = pytest.mark.skipif(not hasattr(rust, "NativeCSVPipeline"), reason="new native pipeline required")


def engine(tmp_path, **config):
    return rust.NativeCSVPipeline(json.dumps({"data_dir": str(tmp_path), "enabled": [], "exempt_paths": [], **config}))


def begin(e, *, ip="8.8.8.8", path="/missing", query=b"", body=b"", now=100.0,
          method="GET", headers=None, country="", exists=False, disabled=(), exempt=False,
          authenticated=False, methods=("GET", "POST"), exhausted=False):
    headers = {**(headers or {}), "AIWAF_COUNTRY": country}
    return e.begin(ip, path, method, headers, query, body, exists, "GET" in methods, "POST" in methods,
                   method in methods, authenticated, set(disabled), exempt, now, "2026-10-12T00:00:00+00:00", exhausted)


def rows(tmp_path, file):
    with (tmp_path / file).open(newline="", encoding="utf-8") as f:
        return list(csv.DictReader(f))


@pytest.mark.parametrize("query,body", [
    (b"q=hello", b""), (b"q=UNION%20SELECT", b""), (b"q=%2527%2520or%25201%253D1", b""),
    (b"q=%FF", b""), (b"", b'{"input":"uni\\u006fn select"}'),
    (b"", '{"input":"你好 UNION SELECT"}'.encode()),
    (b"", '{"input":"UNION SELECT"}'.encode("utf-16")),
    (b"", b'{"union select":null}'), (b"", b'[null,12,false,"hello"]'),
    (b"", b'{"a":"[\\"union select\\"]"}'), (b"", b'bad json'),
    (b"q=union/**/select", b""), (b"q=%27--", b""),
    (b"q=hello", b'{"input":";drop table users"}'),
    (b"", b'{"number":NaN,"input":"uni\\u006fn select"}'),
    (b"", b'{"number":Infinity,"input":"uni\\u006fn select"}'),
    (b"", b'{"number":-Infinity,"input":"uni\\u006fn select"}'),
    (b"", b'{"surrogate":"\\ud800","input":"uni\\u006fn select"}'),
    (b"", b'{"surrogate":"\\udc00","input":"uni\\u006fn select"}'),
    (b"", b'{"surrogate":"\\ud83d\\ude00","input":"uni\\u006fn select"}'),
    (b"", b'{"literal":"NaN \\\\ud800 \\\"abc\\\"","input":"uni\\u006fn select"}'),
    (b"", b'{"z":"uni\\u006fn select","a":"\\u0027--"}'),
    (b"", b'{"a":"uni\\u006fn select","z":"\\u0027--"}'),
    (b"", b'{"a":"uni\\u006fn select","a":"hello"}'),
    (b"", b'{"number":1e999,"input":"uni\\u006fn select"}'),
    (b"", b'{"number":' + b'9' * 500 + b',"input":"uni\\u006fn select"}'),
])
def test_sql_matches_existing_inspector(tmp_path, query, body):
    e = engine(tmp_path, enabled=["ip_keyword_block"], learning=False)
    ctx, status, payload = begin(e, query=query, body=body, exists=True)
    expected = SQLInjectionPolicy().inspect(query, body)
    assert status == (expected.status if expected else 0)
    if expected:
        assert json.loads(payload)["error"] == expected.rule
    e.finish(ctx, status or 200, 100.1, "0")


def test_budget_and_no_keyword_write_on_sql_block(tmp_path):
    e = engine(tmp_path, enabled=["ip_keyword_block"], max_bytes=30)
    assert begin(e, body=b"x" * 31)[1] == 413
    assert begin(e, path="/../shell/shell.php", query=b"q=union select")[1] == 403
    assert rows(tmp_path, "keywords.csv") == []
    assert begin(e, exhausted=True)[1] == 413


def test_nested_structure_limit(tmp_path):
    e = engine(tmp_path, enabled=["ip_keyword_block"])
    assert begin(e, body=(b"[" * 18 + b'"hello"' + b"]" * 18))[1] == 413
    assert begin(e, body=json.dumps([None] * 4100).encode())[1] == 413
    assert begin(e, body=b'[' * 200 + b'null' + b']' * 200)[1] == 413


@pytest.mark.parametrize('encoding', ['utf-8', 'utf-8-sig', 'utf-16', 'utf-16-le', 'utf-16-be', 'utf-32', 'utf-32-le', 'utf-32-be'])
@pytest.mark.parametrize('budget', [30, 64, 256])
def test_encoding_and_budget_parity(tmp_path, encoding, budget):
    e = engine(tmp_path, enabled=['ip_keyword_block'], max_bytes=budget, learning=False)
    for text in ('{"field":"hello"}', '{"field":"uni\\u006fn select"}'):
        body = text.encode(encoding)
        _, status, payload = begin(e, body=body, exists=True)
        expected = SQLInjectionPolicy(max_bytes=budget).inspect(b'', body)
        assert status == (expected.status if expected else 0)
        if expected:
            assert json.loads(payload)['error'] == expected.rule


def test_anomaly_model_history_and_response_learning(tmp_path):
    from aiwaf.core.anomaly import evaluate_anomaly
    keywords = ['.php', 'wp-', 'admin', 'shell']
    model = rust.IsolationForest(n_estimators=20, random_state=42)
    model.fit([[10+i%10, i%2, .01+i%4/1000, i%3, 1+i%4, i%2] for i in range(128)])
    e = engine(tmp_path, enabled=['ai_anomaly'], anomaly_keywords=keywords)
    e.set_model(model)
    path = '/wp-content/admin/shell.php'
    history = [(100-i*.1, path, 404, .1) for i in range(30)]
    e.seed_history('8.8.8.8', [(t, p, s, rt, True) for t, p, s, rt in history])
    expected = evaluate_anomaly(ip='8.8.8.8', path=path, status_code=404, response_time=.1, now=101.,
        history=history, window_seconds=60., model=model, static_keywords=keywords, malicious_keywords=keywords,
        keyword_learning_enabled=False, path_exists=lambda _:False, is_exempt_path=lambda _:False,
        is_malicious_context=lambda _:False)
    ctx, status, _ = begin(e, path=path, now=100.9)
    assert status == 0
    assert (e.finish(ctx, 404, 101., '0')[0] == 403) == expected.block
    e.set_model(None)
    assert e.diagnostics()[0] is False
    ctx, _, _ = begin(e, ip='9.9.9.9', path='/config/freshkeyword', now=101.)
    e.finish(ctx, 404, 101.1, '0')
    assert 'freshkeyword' in {r['keyword'] for r in rows(tmp_path, 'keywords.csv')}


def test_keyword_learning_and_reputation_files(tmp_path):
    e = engine(tmp_path, enabled=["ip_keyword_block"])
    assert begin(e, path="/../shell/shell.php")[1] == 403
    assert "shell" in {row["keyword"] for row in rows(tmp_path, "keywords.csv")}
    blocked = rows(tmp_path, "blacklist.csv")
    assert blocked[0]["ip"] == "8.8.8.8"
    assert int(blocked[0]["offenses"]) == 1
    assert begin(e, path="/known", exists=True)[1] == 403
    assert begin(e, path="/known", exists=True, now=10000)[1] == 0


@pytest.mark.parametrize("backend", ["memory", "csv"])
def test_concurrent_rate_consumption_is_atomic(tmp_path, backend):
    e = engine(tmp_path, enabled=["rate_limit"], rate_backend=backend, rate_max=5, rate_flood=100)
    def consume(_):
        ctx, status, _ = begin(e)
        e.finish(ctx, status or 200, 100.1, "0")
        return status
    with ThreadPoolExecutor(max_workers=8) as pool:
        statuses = list(pool.map(consume, range(30)))
    assert statuses.count(0) == 5
    assert statuses.count(429) == 25
    if backend == "csv":
        second = engine(tmp_path, enabled=["rate_limit"], rate_backend="csv", rate_max=5, rate_flood=100)
        assert begin(second)[1] == 429
    assert begin(e, now=111)[1] == 0


def test_rate_flood_and_soft_blacklist(tmp_path):
    e = engine(tmp_path, enabled=["rate_limit"], rate_max=1, rate_flood=2)
    assert [begin(e)[1] for _ in range(3)] == [0, 429, 403]
    assert rows(tmp_path, "blacklist.csv")[0]["reason"] == "Flood pattern"


def test_exemption_and_disabled_stages(tmp_path):
    e = engine(tmp_path, enabled=["ip_keyword_block", "header_validation"], exempt_paths=["/safe"])
    assert begin(e, path="/safe/child", query=b"q=union select")[1] == 0
    assert begin(e, query=b"q=union select", disabled=["ip_keyword_block", "header_validation"])[1] == 0
    rust.csv_write(str(tmp_path / "whitelist.csv"), ["ip", "added_date"], [["8.8.8.8", "today"]], False)
    assert begin(e, query=b"q=union select")[1] == 0


def test_geo_first_and_header_policy_parity(tmp_path):
    e = engine(tmp_path, enabled=["geo_block", "ip_keyword_block", "header_validation"], geo_block=["cn"])
    ctx, status, _ = begin(e, country="CN", query=b"q=union select")
    assert status == 403
    assert rows(tmp_path, "blacklist.csv")[0]["reason"] == "Geo blocked: CN"
    h = engine(tmp_path / "h", enabled=["header_validation"])
    for headers in ({}, {"HTTP_USER_AGENT":"curl/8.0", "HTTP_ACCEPT":"*/*"},
                    {"HTTP_USER_AGENT":"Mozilla/5.0", "HTTP_ACCEPT":"text/html", "HTTP_ACCEPT_LANGUAGE":"en-US"}):
        expected = header_validation.evaluate_header_policy(headers, min_score=3)
        assert bool(begin(h, headers=headers, ip=str(len(headers)))[1]) == bool(expected)


@pytest.mark.parametrize('backend', ['csv', 'memory'])
def test_honeypot_expiry_auth_and_method(tmp_path, backend):
    e = engine(tmp_path, enabled=["honeypot"], honeypot_backend=backend)
    assert begin(e, now=100)[1] == 0
    assert begin(e, method="POST", now=100.05)[1] == 403
    assert begin(e, method="POST", now=102)[1] == 0
    assert begin(e, method="POST", now=341)[1] == 409
    assert begin(e, method="POST", now=342)[1] == 0
    assert begin(e, authenticated=True, method="POST", methods=["GET"])[1] == 0
    assert begin(e, method="POST", methods=["GET"])[1] == 405


@pytest.mark.parametrize('backend', ['csv', 'memory'])
def test_honeypot_ttl_and_worker_state(tmp_path, backend):
    e = engine(tmp_path, enabled=['honeypot'], honeypot_backend=backend)
    assert begin(e, now=100)[1] == 0
    second = engine(tmp_path, enabled=['honeypot'], honeypot_backend=backend)
    assert begin(second, method='POST', now=100.05)[1] == (403 if backend == 'csv' else 0)
    assert begin(e, method='POST', now=400)[1] == 409  # inclusive TTL edge
    assert begin(e, now=500)[1] == 0
    assert begin(e, method='POST', now=801)[1] == 0  # expired timestamp
    if backend == 'memory':
        assert not (tmp_path / 'pipeline_state.csv').exists()


def test_memory_honeypot_concurrent_refresh_and_expiry(tmp_path):
    e = engine(tmp_path, enabled=['honeypot'], honeypot_backend='memory')
    begin(e, now=100)
    with ThreadPoolExecutor(max_workers=8) as pool:
        statuses = list(pool.map(lambda _: begin(e, method='POST', now=341)[1], range(32)))
    assert statuses.count(409) == 1
    assert statuses.count(0) == 31
    # A later GET survives expiration of the old timestamp and governs POST.
    begin(e, now=342)
    assert begin(e, method='POST', now=342.05)[1] == 403


def test_uuid_response_scoring_and_context_ownership(tmp_path):
    e = engine(tmp_path, enabled=["uuid_tamper"], uuid_threshold=2)
    assert begin(e, query=b"uuid=invalid")[1] == 403
    query = b"uuid=12345678-1234-1234-1234-123456789abc"
    c, _, _ = begin(e, ip="9.9.9.9", query=query)
    assert e.finish(c, 404, 100.1, "0")[0] == 404
    with pytest.raises(RuntimeError, match="already finalized"):
        e.finish(c, 404, 100.1, "0")
    c2, _, _ = begin(e, ip="9.9.9.9", query=query)
    assert e.finish(c2, 404, 100.1, "0")[0] == 403
    other = engine(tmp_path / "other")
    c3, _, _ = begin(e)
    with pytest.raises(ValueError, match="context"):
        other.finish(c3, 200, 100.1, "0")


def test_native_logging_and_missing_capability(tmp_path, monkeypatch):
    e = engine(tmp_path, enabled=["logging"])
    c, _, _ = begin(e, path="/CaseSensitive", headers={"HTTP_USER_AGENT":"browser"})
    e.finish(c, 200, 100.123, "42")
    log = rows(tmp_path, "requests.csv")
    assert log[0]["path"] == "/CaseSensitive"
    assert log[0]["content_length"] == "42"
    assert log[0]["status_code"] == "200"
    assert log[0]["blocked"] == "False"
    from aiwaf.core.csv_pipeline import CSVPipeline
    monkeypatch.delattr(rust, "NativeCSVPipeline")
    with pytest.raises(RuntimeError, match="requires aiwaf-rust"):
        CSVPipeline({"data_dir": str(tmp_path)})


def test_callback_values_cannot_silently_exempt_a_request():
    from aiwaf.core.csv_pipeline import validate_fact_callback, fact_value
    async def async_value(_):
        return True
    with pytest.raises(TypeError, match='synchronous'):
        validate_fact_callback(async_value)
    with pytest.raises(TypeError, match='synchronous'):
        fact_value(lambda value: async_value(value), 'request')
    validate_fact_callback(lambda _:False)
    assert fact_value(lambda _:False, 'request') is False


def test_model_shape_and_existing_log_schema_fail_at_startup(tmp_path):
    e = engine(tmp_path)
    with pytest.raises(ValueError, match='six request features'):
        e.set_model(rust.IsolationForest())
    rust.csv_write(str(tmp_path / 'requests.csv'), ['wrong'], [], False)
    with pytest.raises(ValueError, match='log CSV schema'):
        engine(tmp_path, enabled=['logging'])


def test_clock_adjustment_does_not_turn_success_into_500(tmp_path):
    e = engine(tmp_path, enabled=['logging', 'ai_anomaly'])
    ctx, _, _ = begin(e, now=100.)
    assert e.finish(ctx, 200, 99.9, '0', True)[0] == 200
    assert float(rows(tmp_path, 'requests.csv')[0]['response_time_ms']) >= 0


@pytest.mark.parametrize("config", [
    {"unknown_key":True}, {"sql_mode":"monitor"}, {"rate_backend":"redis"},
    {"enabled":["misspelling"]}, {"rate_window":0}, {"max_bytes":0},
    {"rate_max":30, "rate_flood":20}, {"exempt_paths":["/foo/*"]},
    {"honeypot_backend":"redis"},
])
def test_unsupported_profiles_fail_at_startup(tmp_path, config):
    with pytest.raises(ValueError):
        engine(tmp_path, **config)
