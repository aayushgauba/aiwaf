from django.conf import settings
from django.core.cache import cache
from django.test import override_settings

from .base_test import AIWAFTestCase


class TestModelStorage(AIWAFTestCase):
    @override_settings(
        CACHES={
            "default": {
                "BACKEND": "django.core.cache.backends.locmem.LocMemCache",
                "LOCATION": "aiwaf-model-store",
            }
        },
        AIWAF_MODEL_STORAGE="cache",
        AIWAF_MODEL_CACHE_KEY="aiwaf:test:model",
        AIWAF_MODEL_STORAGE_FALLBACK=False,
    )
    def test_cache_model_storage_roundtrip(self):
        from aiwaf.model_store import load_model_data, save_model_data

        cache.clear()
        model_data = {"model": {"stub": True}, "sklearn_version": "1.0"}
        assert save_model_data(model_data, metadata={"source": "cache-test"}) is True

        loaded = load_model_data()
        assert loaded == model_data

    @override_settings(
        AIWAF_MODEL_STORAGE="db",
        AIWAF_MODEL_STORAGE_FALLBACK=False,
    )
    def test_db_model_storage_roundtrip(self):
        from aiwaf.model_store import load_model_data, save_model_data
        from aiwaf.models import AIModelArtifact

        AIModelArtifact.objects.all().delete()
        model_data = {"model": {"stub": True}, "sklearn_version": "1.0"}
        assert save_model_data(model_data, metadata={"source": "db-test"}) is True

        loaded = load_model_data()
        assert loaded == model_data
