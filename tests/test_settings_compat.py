from django.conf import settings
from django.test import override_settings

from .base_test import AIWAFTestCase


class TestAIWAFSettingsCompat(AIWAFTestCase):
    def _reset_compat(self):
        import aiwaf.settings_compat as settings_compat
        settings_compat._APPLIED = False
        return settings_compat

    def _restore_settings(self, original):
        for name, value in original.items():
            setattr(settings, name, value)
        for name in self._all_setting_names():
            if name not in original and hasattr(settings, name):
                delattr(settings, name)

    def _all_setting_names(self):
        return [
            "AIWAF_STORAGE_MODE",
            "AIWAF_DISABLE_AI",
            "AIWAF_RATE_WINDOW",
            "AIWAF_RATE_MAX",
            "AIWAF_RATE_FLOOD",
            "AIWAF_EXEMPT_PATHS",
            "AIWAF_EXEMPT_IPS",
            "AIWAF_ENABLE_KEYWORD_LEARNING",
            "AIWAF_DYNAMIC_TOP_N",
            "AIWAF_MALICIOUS_KEYWORDS",
            "AIWAF_ENABLE_IP_BLOCKING",
            "AIWAF_MIDDLEWARE_LOGGING",
            "AIWAF_LOG_LEVEL",
            "AIWAF_LOG_FORMAT",
        ]

    @override_settings(
        AIWAF_SETTINGS={
            "STORAGE_TYPE": "django_cache",
            "TRAINING_MODE": False,
            "RATE_LIMITING": {"REQUESTS_PER_MINUTE": 60, "BURST_THRESHOLD": 10},
            "HEADER_VALIDATION": {"ENABLED": True, "BLOCK_THRESHOLD": 5},
            "EXEMPTIONS": {"PATHS": ["/health/"], "IPS": ["127.0.0.1"]},
            "KEYWORD_DETECTION": {
                "ENABLED": True,
                "SENSITIVITY_LEVEL": "medium",
                "CUSTOM_PATTERNS": [".php", "xmlrpc"],
            },
            "IP_BLOCKING": {"ENABLED": True, "WHITELIST": ["192.168.1.0/24"]},
            "LOGGING": {"ENABLED": True, "LEVEL": "WARNING", "FORMAT": "detailed"},
        }
    )
    def test_legacy_settings_mapping(self):
        original = {name: getattr(settings, name) for name in self._all_setting_names() if hasattr(settings, name)}
        try:
            settings_compat = self._reset_compat()
            for name in self._all_setting_names():
                if hasattr(settings, name):
                    delattr(settings, name)
            settings_compat.apply_legacy_settings()

            assert settings.AIWAF_STORAGE_MODE == "django_cache"
            assert settings.AIWAF_DISABLE_AI is True
            assert settings.AIWAF_RATE_WINDOW == 60
            assert settings.AIWAF_RATE_MAX == 60
            assert settings.AIWAF_RATE_FLOOD == 10
            assert settings.AIWAF_EXEMPT_PATHS == ["/health/"]
            assert settings.AIWAF_EXEMPT_IPS == ["127.0.0.1"]
            assert settings.AIWAF_ENABLE_KEYWORD_LEARNING is True
            assert settings.AIWAF_DYNAMIC_TOP_N == 10
            assert settings.AIWAF_ENABLE_IP_BLOCKING is True
            assert settings.AIWAF_MIDDLEWARE_LOGGING is True
            assert settings.AIWAF_LOG_LEVEL == "WARNING"
            assert settings.AIWAF_LOG_FORMAT == "detailed"
            assert settings.AIWAF_MALICIOUS_KEYWORDS == [".php", "xmlrpc"]
        finally:
            self._restore_settings(original)

    @override_settings(
        AIWAF_SETTINGS={
            "RATE_LIMITING": {"REQUESTS_PER_MINUTE": 60, "BURST_THRESHOLD": 10},
            "EXEMPTIONS": {"PATHS": ["/health/"], "IPS": ["127.0.0.1"]},
            "KEYWORD_DETECTION": {"ENABLED": False, "SENSITIVITY_LEVEL": "high"},
            "IP_BLOCKING": {"ENABLED": False},
        }
    )
    def test_explicit_settings_not_overridden(self):
        original = {name: getattr(settings, name) for name in self._all_setting_names() if hasattr(settings, name)}
        try:
            settings.AIWAF_RATE_MAX = 999
            settings.AIWAF_EXEMPT_PATHS = ["/explicit/"]
            settings.AIWAF_ENABLE_KEYWORD_LEARNING = True
            settings.AIWAF_ENABLE_IP_BLOCKING = True

            settings_compat = self._reset_compat()
            settings_compat.apply_legacy_settings()

            assert settings.AIWAF_RATE_MAX == 999
            assert settings.AIWAF_EXEMPT_PATHS == ["/explicit/"]
            assert settings.AIWAF_ENABLE_KEYWORD_LEARNING is True
            assert settings.AIWAF_ENABLE_IP_BLOCKING is True
        finally:
            self._restore_settings(original)
