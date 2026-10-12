"""Shared UUID tamper helpers used by framework adapters."""

from __future__ import annotations

import re
import time
import uuid
from threading import Lock
from .native_runtime import function as native_function


UUID_RE = re.compile(r"^[a-f0-9\-]{36}$")

_UUID_SCORE_STATE = {}
_UUID_SCORE_LOCK = Lock()


def is_valid_uuid(value) -> bool:
    """Return True when ``value`` can be parsed as a UUID."""
    if not value:
        return False
    text = str(value).strip()
    if not text:
        return False
    native = native_function('policy_uuid')
    if native is not None:
        return native(text)
    if UUID_RE.match(text.lower()) is None:
        return False
    try:
        uuid.UUID(text)
    except (ValueError, TypeError, AttributeError):
        return False
    return True


def is_malformed_uuid(value):
    """Return True when a UUID-like input is present but fails format validation."""
    if not value:
        return False
    return not is_valid_uuid(value)


def get_uuid_score_defaults():
    return {
        "enabled": True,
        "window_seconds": 60,
        "block_threshold": 5,
        "malformed_weight": 5,
        "not_found_weight": 1,
        "success_decay": 2,
    }


def record_uuid_signal(subject: str, signal: str, *, now: float | None = None, config: dict | None = None):
    """
    Record a UUID security signal for ``subject`` and return score/block decision.

    Supported signals:
    - ``malformed``: malformed UUID input
    - ``not_found``: valid UUID request ended in 404
    - ``success``: valid UUID request succeeded (<400)
    """
    cfg = get_uuid_score_defaults()
    if config:
        cfg.update(config)
    if not cfg.get("enabled", True):
        return {"score": 0, "blocked": False}

    weight_map = {
        "malformed": int(cfg.get("malformed_weight", 5)),
        "not_found": int(cfg.get("not_found_weight", 1)),
        "success": -int(cfg.get("success_decay", 2)),
    }
    delta = weight_map.get(signal, 0)
    if delta == 0:
        return {"score": 0, "blocked": False}

    ts = float(time.time() if now is None else now)
    window = max(1, int(cfg.get("window_seconds", 60)))
    threshold = max(1, int(cfg.get("block_threshold", 5)))
    key = str(subject or "unknown")

    with _UUID_SCORE_LOCK:
        events = _UUID_SCORE_STATE.get(key, [])
        cutoff = ts - window
        events = [(t, d) for (t, d) in events if t >= cutoff]
        events.append((ts, delta))
        _UUID_SCORE_STATE[key] = events
        score = sum(d for _, d in events)
    return {"score": score, "blocked": score >= threshold}


def clear_uuid_score_state(subject: str | None = None):
    with _UUID_SCORE_LOCK:
        if subject is None:
            _UUID_SCORE_STATE.clear()
            return
        _UUID_SCORE_STATE.pop(str(subject), None)


def collect_uuid_model_fields(models, uuid_field_class):
    """
    Collect UUID lookup candidates from models.

    Returns tuples of ``(Model, field_name)`` for UUID primary keys and unique UUID fields.
    """
    uuid_fields = []
    for model in models:
        pk_field = model._meta.pk
        if isinstance(pk_field, uuid_field_class):
            uuid_fields.append((model, "pk"))
        for field in model._meta.fields:
            if field is pk_field:
                continue
            if isinstance(field, uuid_field_class) and getattr(field, "unique", False):
                uuid_fields.append((model, field.name))
    return uuid_fields


def uuid_exists_in_model_fields(uid, uuid_fields):
    """Return True if ``uid`` exists in any configured model UUID field candidate."""
    for model, field_name in uuid_fields:
        try:
            if field_name == "pk":
                if model.objects.filter(pk=uid).exists():
                    return True
            else:
                if model.objects.filter(**{field_name: uid}).exists():
                    return True
        except (ValueError, TypeError):
            continue
    return False
