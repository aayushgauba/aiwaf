"""Ordered native batching must preserve SQL findings and inspection limits."""
import math
import pytest
from aiwaf.core import sql_injection
from aiwaf.core.native_runtime import native_override


@pytest.fixture
def native():
    module = pytest.importorskip('aiwaf_rust')
    if not hasattr(module, 'policy_sql_signatures'):
        pytest.skip('Requires rebuilt request batching extension')
    return module


@pytest.mark.parametrize('body,query,budget', [
    ({str(i): 'ordinary value' for i in range(200)}, 'q=ordinary', 65536),
    (['union select secret', "x'--"], None, 65536),
    (["x'--", 'union select secret'], None, 65536),
    (["é'--", 'union select secret'], None, 65536),
    (['union select secret', "é'--"], None, 65536),
    ({'nested': [{'email': 'x%2527--'}]}, None, 65536),
    (['x' * 50, "x'--"], None, 30),
    (["x'--", 'x' * 50], None, 30),
    (['x' * 50, 'ordinary'], None, 30),
    (b'{"nested":["safe","x\\u0027--"]}', None, 65536),
])
def test_batched_previous_and_python_parity(native, monkeypatch, body, query, budget):
    policy = sql_injection.SQLInjectionPolicy(max_bytes=budget)
    with native_override(False):
        expected = policy.inspect(query=query, body=body)
    monkeypatch.setattr(sql_injection, 'native_function', lambda name: getattr(native, name, None))
    assert policy.inspect(query=query, body=body) == expected
    monkeypatch.setattr(sql_injection, 'native_function', lambda name: None if name == 'policy_sql_signatures' else getattr(native, name, None))
    assert policy.inspect(query=query, body=body) == expected


def test_batched_calls_are_bounded_and_replace_individual_checks(native, monkeypatch):
    sizes = []
    singles = []
    def batch(values):
        sizes.append(len(values))
        return native.policy_sql_signatures(values)
    def dispatch(name):
        if name == 'policy_sql_signatures':
            return batch
        if name == 'policy_sql_signature':
            return lambda value: singles.append(value) or native.policy_sql_signature(value)
        raise AssertionError('Unexpected native capability')
    monkeypatch.setattr(sql_injection, 'native_function', dispatch)
    body = {f'field{i}': 'normal value' for i in range(200)}
    assert sql_injection.SQLInjectionPolicy().inspect(body=body) is None
    assert len(singles) == 8
    assert sum(sizes) == 392
    assert len(sizes) == math.ceil(392 / 128)
    assert max(sizes) <= 128


def test_early_attack_does_not_prepare_or_check_remaining_fields(native, monkeypatch):
    calls = []
    def single(value):
        calls.append(value)
        return native.policy_sql_signature(value)
    def batch(_):
        raise AssertionError('Early deny should not enter a batch')
    monkeypatch.setattr(sql_injection, 'native_function',
        lambda name: single if name == 'policy_sql_signature' else batch)
    assert sql_injection.SQLInjectionPolicy().inspect(body={'safe': 'value', 'attack': "x'--"}).rule == 'sql_quote_comment'
    assert calls == ["x'--"]


def test_pending_attack_precedes_cycle_limit(native, monkeypatch):
    cycle = []
    cycle.append(cycle)
    body = [cycle, "x'--"]
    policy = sql_injection.SQLInjectionPolicy()
    with native_override(False):
        expected = policy.inspect(body=body)
    monkeypatch.setattr(sql_injection, 'native_function', lambda name: getattr(native, name, None))
    assert policy.inspect(body=body) == expected
    assert expected.rule == 'sql_quote_comment'
