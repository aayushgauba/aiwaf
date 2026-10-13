"""Native histories preserve features, decisions, callbacks, and snapshot isolation."""
from concurrent.futures import ThreadPoolExecutor
import pytest
from aiwaf.core import anomaly, rust_backend
from aiwaf.core.native_runtime import native_override


@pytest.fixture
def native(monkeypatch):
    module = pytest.importorskip('aiwaf_rust')
    if not hasattr(module, 'NativeAnomalyHistory'):
        pytest.skip('Requires rebuilt native anomaly extension')
    monkeypatch.setattr(rust_backend, 'aiwaf_rust', module)
    return module


@pytest.fixture
def model(native):
    forest = native.IsolationForest(n_estimators=20, random_state=42)
    forest.fit([[10+i%10, i%2, .01+i%4/1000, i%3, 1+i%4, i%2] for i in range(128)])
    return forest


def arguments(model, path='/wp-content/admin/shell.php', now=101.):
    return dict(ip='203.0.113.1', path=path, status_code=404, response_time=.1, now=now,
        window_seconds=60., model=model, static_keywords=['.php', 'wp-', 'admin', 'shell'],
        malicious_keywords=['.php', 'wp-', 'admin', 'shell'], keyword_learning_enabled=True,
        path_exists=lambda p: p == '/docs', is_exempt_path=lambda p: p == '/health',
        is_malicious_context=lambda _: True)


def comparable(outcome):
    return outcome.block, outcome.reason, outcome.learned_keywords, list(outcome.updated_history)


@pytest.mark.parametrize('path', ['/docs', '/wp-content/admin/shell.php', '/café', '/İ'])
@pytest.mark.parametrize('count', [0, 20, 200])
def test_native_history_matches_previous_decisions(native, model, monkeypatch, path, count):
    rows = [(100-i*.1, '/wp-content/shell.php' if i%2 else '/docs', 404 if i%2 else 200, .1) for i in range(count)]
    kwargs = arguments(model, path)
    original = anomaly.native_function
    monkeypatch.setattr(anomaly, 'native_function', lambda name: None if name == 'analyze_recent_tuples' else original(name))
    expected = anomaly.evaluate_anomaly(history=rows, **kwargs)
    monkeypatch.setattr(anomaly, 'native_function', original)
    assert comparable(anomaly.evaluate_anomaly(history=native.NativeAnomalyHistory(rows), **kwargs)) == comparable(expected)
    assert comparable(anomaly.evaluate_anomaly(history=rows, **kwargs)) == comparable(expected)


def test_feature_values_and_time_boundaries(native, model):
    rows = [(90., '/docs', 200, .1), (91., '/shell', 404, .1), (101., '/docs', 404, .1),
            (102., '/health', 200, .1), (41., '/expired', 404, .1)]
    history = native.NativeAnomalyHistory(rows).trimmed(101., 60.)
    for known, exempt, status in [(False, False, 404), (True, False, 999), (False, True, 200)]:
        prediction, features = history.predict_current(model, '/shell.php', status, .25, 101.,
            not known and not exempt, ['shell', '.php', 'shell'], ['200', '404', '404'], True)
        expected = anomaly.build_feature_vector(path='/shell.php', status_code=status, response_time=.25,
            now=101., history=anomaly.trim_history(rows, now=101., window_seconds=60.),
            static_keywords=['shell', '.php', 'shell'], status_index_values=['200', '404', '404'],
            path_exists_current=known, is_exempt_path_current=exempt)
        assert features == expected
        assert prediction == anomaly.predict_anomaly(model, expected)


def test_snapshots_are_immutable_and_safe_to_share(native, model):
    rows = [(100-i*.1, '/shell.php', 404, .1) for i in range(30)]
    history = native.NativeAnomalyHistory(rows)
    with ThreadPoolExecutor(max_workers=4) as executor:
        outcomes = list(executor.map(lambda _: comparable(anomaly.evaluate_anomaly(history=history, **arguments(model))), range(16)))
    assert all(outcome == outcomes[0] for outcome in outcomes)
    assert list(history) == rows
    assert history[-1] == rows[-1]
    with pytest.raises(IndexError):
        history[100]


def test_disabled_or_changed_model_returns_python_history(native, model):
    history = native.NativeAnomalyHistory([(100., '/docs', 200, .1)])
    assert isinstance(anomaly.select_native_history(history, model, enabled=False), list)
    assert isinstance(anomaly.select_native_history(history, None), list)
    with native_override(False):
        assert isinstance(anomaly.select_native_history(history, model), list)
        assert isinstance(anomaly.evaluate_anomaly(history=history, **arguments(model)).updated_history, list)
    assert isinstance(anomaly.select_native_history([(100., '/café', 200, .1)], model), list)


def test_route_and_exemption_callbacks_are_refreshed(native, model):
    history = native.NativeAnomalyHistory([(100-i*.1, '/shell.php', 404, .1) for i in range(30)])
    kwargs = arguments(model)
    calls = []
    kwargs['path_exists'] = lambda path: calls.append(path) or False
    native_result = anomaly.evaluate_anomaly(history=history, **kwargs)
    native_calls = calls[:]
    calls.clear()
    previous = anomaly.evaluate_anomaly(history=list(history), **kwargs)
    assert calls == native_calls
    assert comparable(native_result) == comparable(previous)
    kwargs['path_exists'] = lambda _: True
    kwargs['is_exempt_path'] = lambda _: True
    assert comparable(anomaly.evaluate_anomaly(history=history, **kwargs)) == comparable(anomaly.evaluate_anomaly(history=list(history), **kwargs))


@pytest.mark.parametrize('use_native', [False, True])
def test_expiry_keeps_live_unsorted_and_future_histories(native, use_native):
    rows = {
        'expired': [(40., '/old', 404, .1)],  # Exact 60-second boundary expires.
        'empty': [],
        'active': [(99., '/live', 200, .1), (20., '/old', 404, .1)],
        'future': [(110., '/future', 200, .1)],
    }
    cache = {key: native.NativeAnomalyHistory(value) if use_native else value for key, value in rows.items()}
    old_active = cache['active']
    anomaly.prune_inactive_histories(cache, now=100., window_seconds=60.)
    assert set(cache) == {'active', 'future'}
    assert cache['active'] is old_active
    assert list(cache['active']) == rows['active']
    anomaly.prune_inactive_histories(cache, now=float('nan'), window_seconds=60.)
    assert set(cache) == {'active', 'future'}
