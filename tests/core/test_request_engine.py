"""Compiled-stage parity: unsupported inputs fall back before any learning."""
import csv
import json
from types import SimpleNamespace
import pytest
from aiwaf.core.request_engine import prepare_request_engine
from aiwaf.core.sql_injection import SQLInjectionPolicy
from aiwaf.core.ip_keyword import evaluate_keyword_policy
from aiwaf.core.native_runtime import native_override


@pytest.fixture
def native():
    module = pytest.importorskip('aiwaf_rust')
    if not hasattr(module, 'NativeRequestEngine'):
        pytest.skip('Requires compiled request engine')
    return module


def prepare(owner, path, file, counts=False, **overrides):
    kwargs = dict(enabled=True, policy=SQLInjectionPolicy(), path=path, query_context='', query_keys=[], exists=False,
        learning=True, top_n=10, file=file, counts=counts, static={'.php', 'shell'},
        legitimate={'docs'}, exempt=set(), prefixes=[], malicious={'.php', 'shell'})
    kwargs.update(overrides)
    return prepare_request_engine(owner, **kwargs)


@pytest.mark.parametrize('query', [b'', b'q=hello+world', b'q=%2527%2520OR%25201%253D1',
    b'q=1%20UNION%20SELECT', b'q=%FF', b'\x00x', b'{"id":"safe"}', b'%ZZ'])
@pytest.mark.parametrize('body', [None, b'{"id":"safe"}', b'{"id":"1 UNION SELECT secret"}'])
def test_compiled_sql_matches_bounded_legacy(native, tmp_path, query, body):
    file = tmp_path / 'keywords.csv'
    native.csv_write(str(file), ['keyword', 'added_date'], [], False)
    owner = SimpleNamespace()
    compiled = prepare(owner, '/docs', file, exists=True)
    expected = SQLInjectionPolicy().inspect(query, body)
    finding = compiled[0](query, body)
    assert finding == expected
    assert list(csv.DictReader(file.open())) == []


@pytest.mark.parametrize('counts', [False, True])
def test_keyword_learning_and_profile_reuse(native, tmp_path, counts):
    file = tmp_path / ('runtime.csv' if counts else 'keywords.csv')
    native.csv_write(str(file), ['key', 'value', 'expires_at'] if counts else ['keyword', 'added_date'], [], False)
    owner = SimpleNamespace()
    path = '/../shell/shell.php'
    expected = evaluate_keyword_policy(path=path, query_keys=[], path_exists=False, keyword_learning_enabled=True,
        static_keywords={'.php', 'shell'}, dynamic_keywords=[], legitimate_keywords={'docs'}, exempt_keywords=set(),
        safe_prefixes=[], malicious_keywords={'.php', 'shell'}, is_malicious_context=lambda _: True)
    compiled = prepare(owner, path, file, counts)
    assert compiled[0](b'', None) is None
    assert compiled[1][0] == expected
    profile = owner._native_request_engine_profile[1]
    assert prepare(owner, path, file, counts) is not None
    assert owner._native_request_engine_profile[1] is profile
    if counts:
        assert json.loads(native.csv_kv_get(str(file), 'keyword_counts', 0.)) == {'shell': 2}
    else:
        assert native.csv_read_set(str(file), 'keyword', True) == {'shell'}
    prepare(owner, path, file, counts, legitimate={'shell'})
    assert owner._native_request_engine_profile[1] is not profile


def test_unsupported_ranking_disabled_and_custom_hooks(native, tmp_path, monkeypatch):
    file = tmp_path / 'keywords.csv'
    native.csv_write(str(file), ['keyword', 'added_date'], [[str(i), ''] for i in range(20)], False)
    owner = SimpleNamespace()
    compiled = prepare(owner, '/docs', file)
    assert compiled[0](b'', None) is None and compiled[1] == []
    assert prepare(owner, '/café', file) is None
    assert prepare(owner, '/docs', file, enabled=False) is None
    with native_override(False):
        assert prepare(owner, '/docs', file) is None
        assert compiled[0](b'q=1+UNION+SELECT', None).rule == 'sql_union_select'
    policy = SQLInjectionPolicy('monitor')
    assert prepare(owner, '/docs', file, policy=policy) is None
    policy = SQLInjectionPolicy()
    monkeypatch.setattr(policy, 'inspect', lambda *_: None)
    assert prepare(owner, '/docs', file, policy=policy) is None
    policy = SQLInjectionPolicy()
    monkeypatch.setattr(policy, 'enforce', lambda finding: finding)
    assert prepare(owner, '/docs', file, policy=policy) is None


def test_limit_and_sql_off(native, tmp_path):
    file = tmp_path / 'keywords.csv'
    native.csv_write(str(file), ['keyword', 'added_date'], [], False)
    compiled = prepare(SimpleNamespace(), '/docs', file, policy=SQLInjectionPolicy(max_bytes=4))
    assert compiled[0](b'12345', None).status == 413
    assert compiled[1] == []
    compiled = prepare(SimpleNamespace(), '/docs', file, policy=SQLInjectionPolicy('off'), exists=True)
    assert compiled[0](b'q=UNION+SELECT', b'ignored') is None
    assert len(compiled[1]) == 1
