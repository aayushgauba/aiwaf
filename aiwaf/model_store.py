import io
import logging
from django.conf import settings
from django.core.cache import cache

try:
    import joblib
    JOBLIB_AVAILABLE = True
except ImportError:
    joblib = None
    JOBLIB_AVAILABLE = False

logger = logging.getLogger("aiwaf.model_store")


def _normalize_storage_mode(value):
    if not value:
        return "file"
    value = str(value).strip().lower()
    if value in {"filesystem", "fs"}:
        return "file"
    return value


def _load_from_file(path):
    if not JOBLIB_AVAILABLE:
        return None
    if not path:
        return None
    return joblib.load(path)


def _dump_to_bytes(model_data):
    if not JOBLIB_AVAILABLE:
        return None
    buffer = io.BytesIO()
    joblib.dump(model_data, buffer)
    return buffer.getvalue()


def _load_from_bytes(raw):
    if not JOBLIB_AVAILABLE or not raw:
        return None
    return joblib.load(io.BytesIO(raw))


def load_model_data():
    storage_mode = _normalize_storage_mode(getattr(settings, "AIWAF_MODEL_STORAGE", "file"))
    model_path = getattr(settings, "AIWAF_MODEL_PATH", None)
    fallback = getattr(settings, "AIWAF_MODEL_STORAGE_FALLBACK", True)

    if storage_mode == "db":
        try:
            from .models import AIModelArtifact
            record = AIModelArtifact.objects.filter(name="default").first()
            if record:
                data = _load_from_bytes(record.data)
                if data is not None:
                    return data
        except Exception as exc:
            if logger.isEnabledFor(logging.DEBUG):
                logger.debug("AIWAF model DB load failed: %s", exc)
        if fallback:
            return _load_from_file(model_path)
        return None

    if storage_mode == "cache":
        cache_key = getattr(settings, "AIWAF_MODEL_CACHE_KEY", "aiwaf:model")
        entry = cache.get(cache_key)
        if isinstance(entry, dict):
            data = _load_from_bytes(entry.get("data"))
            if data is not None:
                return data
        if fallback:
            return _load_from_file(model_path)
        return None

    return _load_from_file(model_path)


def save_model_data(model_data, metadata=None):
    storage_mode = _normalize_storage_mode(getattr(settings, "AIWAF_MODEL_STORAGE", "file"))
    model_path = getattr(settings, "AIWAF_MODEL_PATH", None)

    if storage_mode == "file":
        if not JOBLIB_AVAILABLE:
            return False
        joblib.dump(model_data, model_path)
        return True

    raw = _dump_to_bytes(model_data)
    if raw is None:
        return False

    if storage_mode == "db":
        try:
            from .models import AIModelArtifact
            AIModelArtifact.objects.update_or_create(
                name="default",
                defaults={"data": raw, "metadata": metadata or {}},
            )
            return True
        except Exception as exc:
            if logger.isEnabledFor(logging.DEBUG):
                logger.debug("AIWAF model DB save failed: %s", exc)
            return False

    if storage_mode == "cache":
        cache_key = getattr(settings, "AIWAF_MODEL_CACHE_KEY", "aiwaf:model")
        cache_timeout = getattr(settings, "AIWAF_MODEL_CACHE_TIMEOUT", None)
        cache.set(cache_key, {"data": raw, "metadata": metadata or {}}, timeout=cache_timeout)
        return True

    return False
