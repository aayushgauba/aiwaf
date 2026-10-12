"""Native dispatch precedence and context isolation across framework adapters."""
import sys
from types import SimpleNamespace

import pytest

from aiwaf.core import native_runtime, rust_backend


@pytest.fixture
def outside_frameworks(monkeypatch):
    monkeypatch.setitem(sys.modules, 'django.conf', None)
    monkeypatch.setitem(sys.modules, 'flask', None)
    monkeypatch.setenv('AIWAF_RUST_CSV', 'true')


def test_environment_disable_and_override_reset(outside_frameworks, monkeypatch):
    assert native_runtime.enabled()
    with native_runtime.native_override(False):
        assert not native_runtime.enabled()
        with native_runtime.native_override(True):
            assert native_runtime.enabled()
        assert not native_runtime.enabled()
    assert native_runtime.enabled()
    monkeypatch.setenv('AIWAF_RUST_CSV', 'false')
    with native_runtime.native_override(True):
        assert not native_runtime.enabled()


@pytest.mark.parametrize('framework', ['flask', 'django'])
def test_framework_settings_precede_environment(outside_frameworks, monkeypatch, framework):
    config = {'AIWAF_USE_RUST': True, 'AIWAF_RUST_CSV': True}
    if framework == 'flask':
        monkeypatch.setitem(sys.modules, 'flask', SimpleNamespace(
            has_app_context=lambda: True, current_app=SimpleNamespace(config=config)))
    else:
        settings = SimpleNamespace(configured=True, **config)
        monkeypatch.setitem(sys.modules, 'django.conf', SimpleNamespace(settings=settings))
    monkeypatch.setenv('AIWAF_RUST_CSV', 'false')
    assert native_runtime.enabled()
    with native_runtime.native_override(False):
        assert not native_runtime.enabled()
    if framework == 'flask':
        config['AIWAF_RUST_CSV'] = False
    else:
        settings.AIWAF_RUST_CSV = False
    assert not native_runtime.enabled()


def test_old_extension_requires_complete_csv_api(outside_frameworks, monkeypatch):
    read = lambda: None
    monkeypatch.setattr(rust_backend, 'aiwaf_rust', SimpleNamespace(csv_read=read))
    assert native_runtime.function('csv_read') is read
    assert native_runtime.csv_function('csv_read') is None
    monkeypatch.setattr(rust_backend, 'aiwaf_rust', None)
    assert native_runtime.function('csv_read') is None


def test_close_logs_works_when_native_disabled(outside_frameworks, monkeypatch):
    closed = []
    monkeypatch.setattr(rust_backend, 'aiwaf_rust', SimpleNamespace(csv_log_close=closed.append))
    with native_runtime.native_override(False):
        native_runtime.close_csv_logs('/tmp/access.csv')
    assert closed == ['/tmp/access.csv']
