"""Capability-gated native CSV and policy dispatch; framework glue stays Python."""
from __future__ import annotations

import os
import sys
from contextlib import contextmanager
from contextvars import ContextVar
from . import rust_backend
import atexit


def close_csv_logs(path=None):
    close = getattr(rust_backend.aiwaf_rust, 'csv_log_close', None)
    if close is not None:
        close(path)


atexit.register(close_csv_logs)

_override = ContextVar('aiwaf_native_override', default=None)


@contextmanager
def native_override(enabled):
    """Allow runtime adapters to disable native work without changing process flags."""
    token = _override.set(bool(enabled))
    try:
        yield
    finally:
        _override.reset(token)


def enabled():
    """Honor framework Rust toggles without importing either framework eagerly."""
    if _override.get() is False:
        return False
    flask = sys.modules.get('flask')
    if flask is not None and flask.has_app_context():
        config = flask.current_app.config
        return bool(config.get('AIWAF_USE_RUST', True) and config.get('AIWAF_RUST_CSV', True))
    django = sys.modules.get('django.conf')
    if django is not None and django.settings.configured:
        return bool(getattr(django.settings, 'AIWAF_USE_RUST', True)
                    and getattr(django.settings, 'AIWAF_RUST_CSV', True))
    return os.environ.get('AIWAF_RUST_CSV', 'true').lower() not in {'0', 'false', 'no', 'off'}


def function(name):
    backend = rust_backend.aiwaf_rust
    if backend is None or not enabled():
        return None
    return getattr(backend, name, None)


def csv_function(name):
    """Require the complete storage API to avoid mixing incompatible native writers."""
    backend = rust_backend.aiwaf_rust
    if backend is None or not enabled():
        return None
    if not all(hasattr(backend, item) for item in
               ('csv_read', 'csv_read_set', 'csv_read_dict', 'csv_contains', 'csv_write')):
        return None
    return getattr(backend, name, None)


def csv_values(row):
    # Match csv.writer's None handling rather than writing the string 'None'.
    return ['' if value is None else str(value) for value in row]
