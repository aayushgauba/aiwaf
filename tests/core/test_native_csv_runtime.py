"""Native/fallback parity and storage coherence tests for the middleware path."""
import json
import os
import random
import subprocess
import sys
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path

import pytest
from aiwaf.core import rust_backend
from aiwaf.core import geo_policy, honeypot, ip_keyword, rate_limit, reputation, uuid_tamper
from aiwaf.core import storage_csv_impl
from aiwaf.core.runtime_storage import CSVStorage


@pytest.fixture
def native(monkeypatch):
    module = pytest.importorskip('aiwaf_rust')
    if not hasattr(module, 'csv_kv_update'):
        pytest.skip('Rebuild the Rust extension to exercise the native CSV runtime')
    monkeypatch.setattr(rust_backend, 'aiwaf_rust', module)
    monkeypatch.setenv('AIWAF_RUST_CSV', 'true')
    yield module
    if hasattr(module, 'csv_log_close'):
        module.csv_log_close(None)


def compare(native, monkeypatch, function, **kwargs):
    monkeypatch.setattr(rust_backend, 'aiwaf_rust', None)
    expected = function(**kwargs)
    monkeypatch.setattr(rust_backend, 'aiwaf_rust', native)
    assert function(**kwargs) == expected


def test_atomic_runtime_exemption_and_geo_lists(native, tmp_path):
    from aiwaf.core.runtime_storage import ExemptionStore, GeoBlockStore
    file = tmp_path / 'policies.csv'
    first = ExemptionStore(CSVStorage(str(file)))
    observer = ExemptionStore(CSVStorage(str(file)))
    def update(i):
        exemptions = ExemptionStore(CSVStorage(str(file)))
        exemptions.add_ip(f'203.0.113.{i}', 'test')
        exemptions.add_pattern(f'198.51.{i}.*')
        GeoBlockStore(CSVStorage(str(file))).add_country(f'C{i}')
    with ThreadPoolExecutor(max_workers=8) as pool:
        list(pool.map(update, range(20)))
    assert len(first.get_exempted_ips()) == 20
    assert len(observer.get_exempted_patterns()) == 20
    assert observer.is_exempted('203.0.113.1')
    assert len(CSVStorage(str(file)).get('exemption_log')) == 20
    assert len(GeoBlockStore(CSVStorage(str(file))).get_countries()) == 20
    assert first.remove_ip('203.0.113.1')
    assert not first.remove_ip('203.0.113.1')
    assert not observer.is_exempted('203.0.113.1')
    assert first.remove_pattern('198.51.1.*')
    assert not observer.is_exempted('198.51.1.2')
    GeoBlockStore(CSVStorage(str(file))).remove_country('c1')
    assert 'C1' not in GeoBlockStore(CSVStorage(str(file))).get_countries()
    first.storage.delete('exemptions')
    assert observer.get_exempted_ips() == set()
    assert observer.get_exempted_patterns() == []


def test_process_policy_updates_preserve_exemptions_and_geo(native, tmp_path):
    path = str(tmp_path / 'worker-policies.csv')
    code = '''import aiwaf_rust,sys
for i in range(10):
    value = sys.argv[2]+str(i)
    aiwaf_rust.csv_runtime_list_update(sys.argv[1], 'add_ip', value, 'test', 100)
    aiwaf_rust.csv_runtime_list_update(sys.argv[1], 'add_country', value, '', 100)
'''
    env = dict(os.environ, PYTHONPATH=str(Path(native.__file__).parent))
    workers = [subprocess.Popen([sys.executable, '-c', code, path, f'W{i}:'], env=env)
               for i in range(3)]
    assert all(worker.wait(timeout=30) == 0 for worker in workers)
    assert len(json.loads(native.csv_kv_get(path, 'exemptions', 100))['ips']) == 30
    assert len(json.loads(native.csv_kv_get(path, 'geo_blocked_countries', 100))) == 30
    assert len(json.loads(native.csv_kv_get(path, 'exemption_log', 100))) == 30


def test_malformed_runtime_policy_update_does_not_change_file(native, tmp_path):
    from aiwaf.core.runtime_storage import ExemptionStore
    store = CSVStorage(str(tmp_path / 'bad.csv'))
    store.set('exemptions', {'ips': ['203.0.113.7'], 'patterns': []})
    store.set('exemption_log', {'invalid': True})
    before = store.file_path.read_bytes()
    with pytest.raises(OSError):
        ExemptionStore(store).add_ip('203.0.113.8')
    assert store.file_path.read_bytes() == before


def test_atomic_flask_policy_list_mutations(native, tmp_path):
    from flask import Flask
    from aiwaf.flask import storage
    app = Flask(__name__)
    app.config.update(AIWAF_USE_CSV=True, AIWAF_DATA_DIR=str(tmp_path))
    def update(i):
        with app.app_context():
            storage.add_geo_blocked_country(f'C{i}')
            storage.add_ip_whitelist(f'203.0.113.{i}')
            storage.add_path_exemption(f'/p{i}', 'test')
            if i % 2:
                storage.remove_geo_blocked_country(f'C{i}')
                storage.remove_ip_whitelist(f'203.0.113.{i}')
                storage.remove_path_exemption(f'/p{i}')
    with ThreadPoolExecutor(max_workers=8) as pool:
        list(pool.map(update, range(20)))
    with app.app_context():
        assert storage.get_geo_blocked_countries() == {f'C{i}' for i in range(0, 20, 2)}
        assert storage.get_path_exemptions() == {f'/p{i}' for i in range(0, 20, 2)}
        assert storage.is_country_geo_blocked('c0')
        assert storage.is_country_geo_blocked('c0')  # Reads must never remove a policy.
        for i in range(20):
            assert storage.is_ip_whitelisted(f'203.0.113.{i}') == (i % 2 == 0)
        storage.add_path_exemption('/MiXeD', 'legacy')
        storage.remove_path_exemption('/mixed')
        assert '/MiXeD' not in storage.get_path_exemptions()


def test_combined_keyword_decision_and_learning(native, tmp_path):
    file = str(tmp_path / 'keywords.csv')
    args = ('/../evil/attack', '', set(), False, True, {'shell'}, set(),
            set(), set(), [], {'shell'})
    expected = native.policy_keyword_flask(*args)
    def apply(_):
        return native.csv_keyword_apply(file, 'today', *args)
    with ThreadPoolExecutor(max_workers=8) as pool:
        results = list(pool.map(apply, range(20)))
    assert all(result == expected for result in results)
    headers, rows = native.csv_read(file, True)
    assert headers == ['keyword', 'added_date']
    assert {row[0] for row in rows} == set(expected[1])
    assert len(rows) == len(set(expected[1]))


@pytest.mark.parametrize('durable', [False, True])
def test_native_log_append_flushes_before_return(native, tmp_path, durable):
    path = str(tmp_path / 'access.csv')
    native.csv_log_append(path, ['id', 'path'], ['seed', '/initial'], durable)
    assert len(native.csv_read(path, True)[1]) == 1
    with ThreadPoolExecutor(max_workers=8) as pool:
        list(pool.map(lambda i: native.csv_log_append(path, ['id', 'path'],
            [str(i), '/comma,quote"newline\n'], durable), range(30)))
    headers, rows = native.csv_read(path, True)
    assert headers == ['id', 'path']
    assert len(rows) == 31
    assert {row[0] for row in rows} == {'seed'} | {str(i) for i in range(30)}
    assert all(row[1] == '/comma,quote"newline\n' for row in rows if row[0] != 'seed')


@pytest.mark.parametrize('wildcards,prefix', [(True, True), (True, False), (False, True), (False, False)])
def test_native_path_exemptions_match_fallback(native, monkeypatch, wildcards, prefix):
    from aiwaf.core.exemptions import is_path_exempt
    paths = ['', '/', '/health', '/health/', '/healthz', '/health/child',
        ' API//V1/Things ', '/api/v1/things', '/api/v2/test', '/a/b/c', '/a/x/c',
        '/a/[x]', '/a/]', '/x/Ä', '/a\\b', '/a/b\n', '/a/b/c/d']
    patterns = [['/health'], ['/api/*'], ['/a/*/c'], ['/a/*[!x]'], ['/a/*[z-a]'],
        ['/a/*[[]'], ['/a/*[]]'], ['/x/*'], ['/'], ['/a/*?'], ['/a/*b*c*d*'],
        ['/a\\*'], ['', None, '/health']]
    for path in paths:
        for exemptions in patterns:
            monkeypatch.setattr(rust_backend, 'aiwaf_rust', None)
            expected = is_path_exempt(path, exemptions, wildcards, prefix)
            monkeypatch.setattr(rust_backend, 'aiwaf_rust', native)
            assert is_path_exempt(path, exemptions, wildcards, prefix) == expected, (path, exemptions)


def test_native_ip_exemptions_match_fallback(native, monkeypatch):
    from aiwaf.core.exemptions import is_ip_exempt
    addresses = ['203.0.113.7', '203.0.114.7', '192.0.2.1', 'bad-ip',
        '2001:db8::1', '2001:DB8::1', '2001:db9::1', 'fe80::1%eth0', '127.0.0.1']
    patterns = [['203.0.113.*'], ['203.0.113.7/24'], ['0.0.0.0/0'],
        ['203.0.113.0/255.255.255.0'], ['203.0.113.0/0.0.0.255'],
        ['2001:db8::/32'], ['::/0'], ['fe80::/10'], ['203.0.113.[0-9]'],
        ['invalid/88'], ['2001:db8::*'], []]
    for ip in addresses:
        for rules in patterns:
            for exact in [set(), {'2001:DB8::1'}, {'203.0.113.7'}]:
                monkeypatch.setattr(rust_backend, 'aiwaf_rust', None)
                expected = is_ip_exempt(ip, exact, rules)
                monkeypatch.setattr(rust_backend, 'aiwaf_rust', native)
                assert is_ip_exempt(ip, exact, rules) == expected, (ip, exact, rules)


def test_native_combined_route_plans_match_fallback(native, monkeypatch):
    from aiwaf.core.route_plan import get_route_execution_plan, clear_route_plan_cache
    from aiwaf.core.exemptions import get_path_rule_for_path
    rng = random.Random(71)
    names = ['rate_limit', 'header_validation', 'geo_block', 'ai_anomaly', 'logging']
    for _ in range(100):
        rules = [{'PREFIX': prefix, 'DISABLE': rng.sample(names, rng.randrange(5)),
                  'RATE_LIMIT': {'MAX': rng.randrange(20)}}
                 for prefix in ['/api/', '/api/v1/', '/api/v1/', '/']]
        kwargs = dict(path=rng.choice(['/api', '/api/v1/items', '/apix', '/other', '//API//v1/']),
            rules=rules, fully_exempt=rng.choice([True, False]),
            exempt_middlewares=rng.sample(names, rng.randrange(5)),
            required_middlewares=rng.sample(names, rng.randrange(5)))
        monkeypatch.setattr(rust_backend, 'aiwaf_rust', None)
        clear_route_plan_cache()
        expected = get_route_execution_plan(**kwargs)
        expected_rule = get_path_rule_for_path(kwargs['path'], rules)
        monkeypatch.setattr(rust_backend, 'aiwaf_rust', native)
        clear_route_plan_cache()
        assert get_route_execution_plan(**kwargs) == expected
        assert get_path_rule_for_path(kwargs['path'], rules) is expected_rule


def test_flask_native_combined_exemptions_observe_csv_changes(native, tmp_path):
    from flask import Flask, request
    from aiwaf.flask import storage, utils
    app = Flask(__name__)
    app.config.update(AIWAF_USE_CSV=True, AIWAF_DATA_DIR=str(tmp_path),
                      AIWAF_EXEMPT_PATHS=['/health'])
    with app.test_request_context('/unknown', environ_base={'REMOTE_ADDR': '203.0.113.7'}):
        assert not utils.is_exempt(request)
        storage.add_ip_whitelist('203.0.113.7')
        assert utils.is_exempt(request)
        storage.remove_ip_whitelist('203.0.113.7')
        assert not utils.is_exempt(request)
        storage.add_path_exemption('/unknown')
        assert utils.is_exempt(request)
        storage.remove_path_exemption('/unknown')
        assert not utils.is_exempt(request)
    with app.test_request_context('/health/child'):
        assert utils.is_exempt(request)


def test_native_exemption_toggle_preserves_fallback(native, monkeypatch):
    from aiwaf.core.exemptions import is_path_exempt
    monkeypatch.setenv('AIWAF_RUST_CSV', 'false')
    assert is_path_exempt('/health/ok', ['/health'], True, True)


def test_runtime_block_and_keyword_updates_are_atomic(native, tmp_path):
    from aiwaf.core.runtime_storage import BlacklistStore, KeywordStore
    path = tmp_path / 'runtime.csv'
    backend = CSVStorage(str(path))
    blocks = BlacklistStore(backend)
    keywords = KeywordStore(backend)
    def update(_):
        blocks.block_ip('203.0.113.8', 'Keyword probe')
        keywords.add_keyword('Probe', 2)
    with ThreadPoolExecutor(max_workers=8) as pool:
        list(pool.map(update, range(20)))
    assert blocks.get_block_info('203.0.113.8')['offenses'] == 20
    assert blocks.get_block_info('203.0.113.8')['duration'] == 86400
    assert len(backend.get('block_log')) == 20
    assert backend.get('keyword_counts') == {'probe': 40}
    keywords.remove_keyword('Probe')
    assert backend.get('keyword_counts') == {}


def test_runtime_block_native_fallback_metadata_parity(native, monkeypatch, tmp_path):
    from aiwaf.core.runtime_storage import BlacklistStore, MemoryStorage
    monkeypatch.setattr('aiwaf.core.runtime_storage.time.time', lambda: 100.0)
    expected = MemoryStorage()
    actual = CSVStorage(str(tmp_path / 'blocks.csv'))
    for duration in [None, 60, 0, -1]:
        for backend in [expected, actual]:
            store = BlacklistStore(backend)
            store.block_ip('203.0.113.9', 'Keyword probe', duration, {'path': '/test'})
        assert actual.get('blocked:203.0.113.9') == expected.get('blocked:203.0.113.9')
        assert actual.get('block_log') == expected.get('block_log')


def test_csv_rate_cache_atomic_actions_and_expiration(native, tmp_path):
    from aiwaf.core.cache_backend import CSVRateCache
    from aiwaf.core.rate_limit import consume_rate_limit
    cache = CSVRateCache(tmp_path / 'rates.csv')
    def consume(_):
        return consume_rate_limit(cache, 'burst', now=100, window_seconds=10,
            max_requests=20, flood_threshold=40).action
    with ThreadPoolExecutor(max_workers=16) as pool:
        actions = list(pool.map(consume, range(65)))
    assert actions.count('allow') == 20
    assert actions.count('throttle') == 20
    assert actions.count('flood_block') == 25
    decision = consume_rate_limit(cache, 'burst', now=110, window_seconds=10,
        max_requests=20, flood_threshold=40)
    assert decision.action == 'allow' and decision.count == 1


@pytest.mark.parametrize('path,query,exists', [('/wp/test.php', '', False),
    ('/api/shell', 'shell=union+select', True), ('/x/../evil', '', False),
    ('/profile', '', True), ('/.env', '', False)])
def test_flask_context_native_matches_python(native, monkeypatch, path, query, exists):
    def context(seg):
        return ((seg in query and any(t in query for t in
            ('union', 'select', 'drop', 'insert', 'script', 'alert', 'eval')))
            or '../' in path or '..\\' in path or (seg.startswith('.') and not exists)
            or (not exists and any(ext in seg for ext in ('.php', '.asp', '.jsp', '.cgi'))))
    static = {'.php', '.env', 'shell'}
    monkeypatch.setattr(rust_backend, 'aiwaf_rust', None)
    expected = ip_keyword.evaluate_keyword_policy(path=path, query_keys=['shell'],
        path_exists=exists, keyword_learning_enabled=True, static_keywords=static,
        dynamic_keywords=['evil'], legitimate_keywords={'profile'}, exempt_keywords=set(),
        safe_prefixes=['api'], malicious_keywords=static, is_malicious_context=context)
    actual = native.policy_keyword_flask(path, query, {'shell'}, exists, True,
        static, {'evil'}, {'profile'}, set(), ['api'], static)
    assert ip_keyword.KeywordDecision(*actual) == expected


def test_native_presence_updates_preserve_other_workers(native, tmp_path):
    path = str(tmp_path / 'keywords.csv')
    def update(i):
        native.csv_set_update(path, ['keyword', 'added_date'], str(i), [str(i), 'today'], False)
    with ThreadPoolExecutor(max_workers=8) as pool:
        list(pool.map(update, range(30)))
    assert len(native.csv_read_set(path, 'keyword', True)) == 30
    native.csv_set_update(path, ['keyword', 'added_date'], '0', [], True)
    assert len(native.csv_read_set(path, 'keyword', True)) == 29


def test_sql_native_signature_parity(native, monkeypatch):
    from aiwaf.core.sql_injection import SQLInjectionPolicy
    samples = ['normal search', "x UNION SELECT password", "x union/**/select y",
        "x' or 1=1", "x' AND true", "' OR 'a'='a'", "x'--", 'x;drop table users',
        'x; update users set name=1', 'union%2520select', '{"key":"union select"}',
        'UNION ALL SELECT', 'unionselector', 'éunion select']
    rng = random.Random(42)
    samples += [''.join(rng.choice('union SELECT0123;\'/*- _') for _ in range(80)) for _ in range(100)]
    for sample in samples:
        monkeypatch.setattr(rust_backend, 'aiwaf_rust', None)
        expected = SQLInjectionPolicy().inspect(body=sample)
        monkeypatch.setattr(rust_backend, 'aiwaf_rust', native)
        assert SQLInjectionPolicy().inspect(body=sample) == expected


def test_flask_csv_rate_backend_selection(native, tmp_path):
    from flask import Flask
    from aiwaf.flask.rate_limit_middleware import _resolve_rate_cache_backend
    app = Flask(__name__)
    app.config.update(AIWAF_RATE_CACHE_BACKEND='csv', AIWAF_DATA_DIR=str(tmp_path))
    backend = _resolve_rate_cache_backend(app)
    assert backend.is_shared
    with app.app_context():
        decision = backend.consume_rate_limit('test', now=100, window_seconds=10,
            max_requests=1, flood_threshold=3)
        assert decision.action == 'allow'
        assert (tmp_path / 'rate_buckets.csv').exists()
        app.config['AIWAF_USE_RUST'] = False
        with pytest.raises(RuntimeError):
            backend.consume_rate_limit('test', now=101, window_seconds=10,
                max_requests=1, flood_threshold=3)


def test_policy_parity(native, monkeypatch):
    rng = random.Random(37)
    for _ in range(100):
        compare(native, monkeypatch, rate_limit.evaluate_rate_limit,
                timestamps=[rng.uniform(0, 100) for _ in range(30)], now=100,
                window_seconds=rng.choice([0, 1, 10, 60]), max_requests=10, flood_threshold=20)
    for score in [0, 20, 59, 60, 79, 80, 100]:
        for offenses in [0, 1, 2, 3]:
            compare(native, monkeypatch, reputation.evaluate_reputation,
                    existing=dict(score=score, offenses=offenses, reasons=['header', 'HEADER']),
                    reason='Keyword block: probe path', now=100)
    for elapsed in [0, .05, .1, 1, 2, 300, 301]:
        for path in ['/login/', '/form/']:
            compare(native, monkeypatch, honeypot.evaluate_form_timing,
                    now=1000+elapsed, get_time=1000, path=path, min_form_time=2, max_page_time=300)
    for country in ['', 'us', ' CN ']:
        for allow in [[], ['US']]:
            compare(native, monkeypatch, geo_policy.evaluate_geo_policy,
                    country=country, allow_countries=allow, block_countries=['CN'], dynamic_blocked=['US'])
    for value in ['', 'abc', '12345678-1234-1234-1234-123456789abc', 'ffffffffffffffffffffffffffffffff----']:
        compare(native, monkeypatch, uuid_tamper.is_valid_uuid, value=value)


@pytest.mark.parametrize('path', ['/wp-content/plugins/pods/init.php', '/.env', '/.git/config',
    '/pricing', '/docs/exploit', '/evil/attack', '/api/shell', '/x/union+select', '/x/../test'])
@pytest.mark.parametrize('exists', [False, True])
def test_keyword_decisions_match(native, monkeypatch, path, exists):
    compare(native, monkeypatch, ip_keyword.evaluate_keyword_policy, path=path,
            query_keys=['cmd'], path_exists=exists, keyword_learning_enabled=True,
            static_keywords=['shell', 'wp-', '.php'], dynamic_keywords=['attack'],
            legitimate_keywords={'docs', 'pricing'}, exempt_keywords={'allowed'},
            safe_prefixes=['api'], malicious_keywords={'shell', 'attack'},
            is_malicious_context=lambda segment: segment in {'shell', 'attack', 'test'})


def test_native_and_python_csv_interoperate(native, monkeypatch, tmp_path):
    storage_csv_impl.ensure_all(tmp_path)
    storage_csv_impl.append_keyword(tmp_path, 'quote,"and\nnewline')
    assert storage_csv_impl.read_keywords(tmp_path) == {'quote,"and\nnewline'}
    # Warm the native cache, then mutate via the original Python writer.
    monkeypatch.setattr(rust_backend, 'aiwaf_rust', None)
    storage_csv_impl.append_keyword(tmp_path, 'external')
    monkeypatch.setattr(rust_backend, 'aiwaf_rust', native)
    assert storage_csv_impl.read_keywords(tmp_path) == {'quote,"and\nnewline', 'external'}
    storage_csv_impl.append_blacklist(tmp_path, '203.0.113.1', 'probe', '{}',
                                     dict(score=60, offenses=3, expires_at=150, duration=50))
    result = storage_csv_impl.read_blacklist(tmp_path)['203.0.113.1']
    assert result['score'] == 60
    assert result['expires_at'] == 150


def test_cached_index_refreshes_after_rewrite(native, tmp_path):
    path = str(tmp_path/'index.csv')
    native.csv_write(path, ['ip', 'reason'], [['one', 'old']], False)
    assert native.csv_contains(path, 'ip', 'one', True)
    native.csv_write(path, ['ip', 'reason'], [['two', 'new']], False)
    assert not native.csv_contains(path, 'ip', 'one', True)
    assert native.csv_lookup(path, 'ip', 'two') == {'ip': 'two', 'reason': 'new'}


def test_unicode_csv_and_invalid_schema_failures(native, tmp_path):
    path = str(tmp_path/'unicode.csv')
    native.csv_write(path, ['keyword'], [['日本語, "quoted"\nline']], False)
    assert native.csv_read_set(path, 'keyword', True) == {'日本語, "quoted"\nline'}
    with pytest.raises(OSError, match='schema'):
        native.csv_kv_update(path, 'x', 'y', None, 100)
    assert native.csv_read_set(path, 'keyword', True) == {'日本語, "quoted"\nline'}


def test_shared_csv_instances_refresh_and_preserve_keys(native, tmp_path):
    path = tmp_path/'shared.csv'
    first, second = CSVStorage(str(path)), CSVStorage(str(path))
    first.set('blocked:one', {'score': 60})
    assert second.get('blocked:one') == {'score': 60}
    second.set('blocked:two', {'score': 80})
    assert first.get('blocked:two') == {'score': 80}
    assert set(first.get_all_keys('blocked:*')) == {'blocked:one', 'blocked:two'}
    first.delete('blocked:one')
    assert second.get('blocked:one') is None
    native.csv_kv_update(str(path), 'expired', '42', 50, 40)
    assert native.csv_kv_get(str(path), 'expired', 51) is None
    assert 'expired' not in native.csv_kv_keys(str(path), 51)


def test_threaded_csv_updates_do_not_lose_rows(native, tmp_path):
    path = str(tmp_path/'threaded.csv')
    with ThreadPoolExecutor(max_workers=8) as executor:
        list(executor.map(lambda i: native.csv_kv_update(path, str(i), json.dumps(i), None, 100), range(100)))
    assert len(native.csv_kv_keys(path, 100)) == 100


def test_concurrent_blacklist_reputation_updates(native, tmp_path):
    storage_csv_impl.ensure_all(tmp_path)
    with ThreadPoolExecutor(max_workers=8) as executor:
        list(executor.map(lambda _: storage_csv_impl.native_block_blacklist(
            tmp_path, '213.35.106.249', 'Keyword block: probe path'), range(20)))
    entry = storage_csv_impl.read_blacklist_entry(tmp_path, '213.35.106.249')
    assert entry['offenses'] == 20
    assert entry['score'] == 100
    assert entry['duration'] == 86400
    storage_csv_impl.native_remove_blacklist(tmp_path, '213.35.106.249')
    assert storage_csv_impl.read_blacklist_entry(tmp_path, '213.35.106.249') is None


def test_native_blacklist_expiry_and_permanent_entries(native, tmp_path, monkeypatch):
    monkeypatch.setattr(storage_csv_impl.time, 'time', lambda: 100)
    storage_csv_impl.native_block_blacklist(tmp_path, 'one', 'Keyword probe', duration=10)
    storage_csv_impl.native_block_blacklist(tmp_path, 'two', 'manual', duration=0)
    assert storage_csv_impl.native_check_blacklist(tmp_path, 'one', 109)
    assert not storage_csv_impl.native_check_blacklist(tmp_path, 'one', 110)
    assert storage_csv_impl.read_blacklist_entry(tmp_path, 'one') is None
    assert storage_csv_impl.native_check_blacklist(tmp_path, 'two', 100000)


def test_process_csv_updates_do_not_lose_rows(native, tmp_path):
    path = str(tmp_path/'workers.csv')
    code = 'import aiwaf_rust,sys; [aiwaf_rust.csv_kv_update(sys.argv[1],sys.argv[2]+str(i),str(i),None,100) for i in range(30)]'
    env = dict(os.environ, PYTHONPATH=str(Path(native.__file__).parent))
    workers = [subprocess.Popen([sys.executable, '-c', code, path, str(i)+':'], env=env)
               for i in range(3)]
    assert all(worker.wait(timeout=30) == 0 for worker in workers)
    assert len(native.csv_kv_keys(path, 100)) == 90


def test_flask_php_probe_native_path(native, tmp_path):
    flask = pytest.importorskip('flask')
    from aiwaf.flask.ip_and_keyword_block_middleware import IPAndKeywordBlockMiddleware
    app = flask.Flask(__name__)
    app.config.update(AIWAF_USE_CSV=True, AIWAF_USE_RUST=True,
                      AIWAF_EXEMPT_PATHS=[], AIWAF_DATA_DIR=str(tmp_path))
    IPAndKeywordBlockMiddleware(app)
    response = app.test_client().get('/wp-content/plugins/pods/init.php',
                                    environ_base={'REMOTE_ADDR': '213.35.106.249'})
    assert response.status_code == 403
    assert response.json == {'error': 'blocked'}


def test_disable_and_old_extension_fallback(native, monkeypatch, tmp_path):
    import sys
    from aiwaf.core.native_runtime import csv_function
    # This tests environment dispatch outside framework contexts. Other suites
    # may have configured Django during collection; its settings take precedence.
    monkeypatch.setitem(sys.modules, 'django.conf', None)
    monkeypatch.setitem(sys.modules, 'flask', None)
    monkeypatch.setenv('AIWAF_RUST_CSV', 'false')
    assert csv_function('csv_read') is None
    storage_csv_impl.append_keyword(tmp_path, 'python')
    monkeypatch.setenv('AIWAF_RUST_CSV', 'true')
    assert storage_csv_impl.read_keywords(tmp_path) == {'python'}
    monkeypatch.setattr(rust_backend, 'aiwaf_rust', object())
    assert csv_function('csv_read') is None


def test_csv_rate_cache_administrative_lifecycle(native, tmp_path):
    from aiwaf.core.cache_backend import CSVRateCache
    from aiwaf.core.native_runtime import native_override
    cache = CSVRateCache(tmp_path / 'rates.csv')
    cache.set('bucket', [1, 2], ttl_seconds=60)
    assert cache.get('bucket') == [1, 2]
    cache.clear()
    assert cache.get('bucket') is None
    with native_override(False), pytest.raises(RuntimeError, match='requires the native'):
        cache.clear()
