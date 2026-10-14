from unittest.mock import patch

from django.test import override_settings

from tests.django.base_test import AIWAFMiddlewareTestCase
from aiwaf.django.middleware import (
    GeoBlockMiddleware,
    HeaderValidationMiddleware,
    HoneypotTimingMiddleware,
    IPAndKeywordBlockMiddleware,
    RateLimitMiddleware,
    UUIDTamperMiddleware,
)
from aiwaf.core.method_validation import ACTION_BLOCK as METHOD_BLOCK


class _Decision:
    def __init__(self, block_reason=None, learned_keywords=None):
        self.block_reason = block_reason
        self.learned_keywords = learned_keywords or []


class ExtendedInfoBlockPathsDjangoTests(AIWAFMiddlewareTestCase):
    def _assert_extended_info(self, block_mock, path):
        self.assertTrue(block_mock.called, "expected BlocklistManager.block to be called")
        info = block_mock.call_args.kwargs.get("extended_request_info")
        self.assertIsNotNone(info)
        self.assertEqual(info.get("path"), path)
        self.assertIn(info.get("method"), {"GET", "POST", "PUT", "DELETE", "PATCH", "HEAD", "OPTIONS"})

    @override_settings(AIWAF_BLOCKLIST_STORE_EXTENDED_INFO=True)
    def test_django_ip_keyword_block_attaches_extended_info(self):
        request = self.create_request("/wp-admin", headers={"REMOTE_ADDR": "203.0.113.10"})
        mw = IPAndKeywordBlockMiddleware(self.mock_get_response)
        with patch("aiwaf.django.middleware.BlocklistManager.is_blocked", return_value=False), \
             patch("aiwaf.django.middleware.BlocklistManager.block", return_value=True) as mock_block, \
             patch("aiwaf.django.middleware.evaluate_keyword_policy", return_value=_Decision(block_reason="forced")):
            mw(request)
        self._assert_extended_info(mock_block, "/wp-admin")

    @override_settings(AIWAF_BLOCKLIST_STORE_EXTENDED_INFO=True)
    def test_django_header_validation_block_attaches_extended_info(self):
        request = self.create_request("/blocked/", headers={"REMOTE_ADDR": "203.0.113.11"})
        mw = HeaderValidationMiddleware(self.mock_get_response)
        with patch("aiwaf.django.middleware.BlocklistManager.is_blocked", return_value=False), \
             patch("aiwaf.django.middleware.BlocklistManager.block", return_value=True) as mock_block, \
             patch("aiwaf.django.middleware.core_header_validation.evaluate_header_policy", return_value="forced header failure"):
            mw.process_request(request)
        self._assert_extended_info(mock_block, "/blocked/")

    @override_settings(
        AIWAF_BLOCKLIST_STORE_EXTENDED_INFO=True,
        AIWAF_RATE_WINDOW=60,
        AIWAF_RATE_MAX=100,
        AIWAF_RATE_FLOOD=1,
    )
    def test_django_rate_limit_flood_block_attaches_extended_info(self):
        request = self.create_request("/rl/", headers={"REMOTE_ADDR": "203.0.113.12"})
        mw = RateLimitMiddleware(self.mock_get_response)
        with patch("aiwaf.django.middleware.BlocklistManager.is_blocked", return_value=False), \
             patch("aiwaf.django.middleware.BlocklistManager.block", return_value=True) as mock_block:
            mw(request)
            mw(request)
        self._assert_extended_info(mock_block, "/rl/")

    @override_settings(AIWAF_BLOCKLIST_STORE_EXTENDED_INFO=True)
    def test_django_honeypot_block_attaches_extended_info(self):
        request = self.create_request("/web/test/", method="POST", headers={"REMOTE_ADDR": "203.0.113.13"})
        mw = HoneypotTimingMiddleware(self.mock_get_response)
        forced = type(
            "Decision",
            (),
            {
                "action": METHOD_BLOCK,
                "reason": "forced honeypot block",
                "message": "forced honeypot block",
                "status_code": 405,
            },
        )()
        with patch("aiwaf.django.middleware.BlocklistManager.is_blocked", return_value=False), \
             patch("aiwaf.django.middleware.BlocklistManager.block", return_value=True) as mock_block:
            with patch("aiwaf.django.middleware.evaluate_method_policy", return_value=forced):
                mw.process_request(request)
        self._assert_extended_info(mock_block, "/web/test/")

    @override_settings(
        AIWAF_BLOCKLIST_STORE_EXTENDED_INFO=True,
        AIWAF_GEO_BLOCK_ENABLED=True,
        AIWAF_GEO_BLOCK_COUNTRIES=["US"],
    )
    def test_django_geo_block_attaches_extended_info(self):
        request = self.create_request("/geo/", headers={"REMOTE_ADDR": "203.0.113.14"})
        mw = GeoBlockMiddleware(self.mock_get_response)
        with patch("aiwaf.django.middleware.BlocklistManager.is_blocked", return_value=False), \
             patch("aiwaf.django.middleware.BlocklistManager.block", return_value=True) as mock_block, \
             patch("aiwaf.django.middleware.lookup_country", return_value="US"):
            mw.process_request(request)
        self._assert_extended_info(mock_block, "/geo/")

    @override_settings(AIWAF_BLOCKLIST_STORE_EXTENDED_INFO=True)
    def test_django_uuid_tamper_block_attaches_extended_info(self):
        request = self.create_request("/items/bad-uuid/", headers={"REMOTE_ADDR": "203.0.113.15"})
        mw = UUIDTamperMiddleware(self.mock_get_response)

        def _view_func():
            return None

        _view_func.__module__ = "tests.fakeviews"

        with patch("aiwaf.django.middleware.BlocklistManager.is_blocked", return_value=False), \
             patch("aiwaf.django.middleware.BlocklistManager.block", return_value=True) as mock_block:
            mw.process_view(request, _view_func, (), {"uuid": "bad-uuid"})
        self._assert_extended_info(mock_block, "/items/bad-uuid/")
