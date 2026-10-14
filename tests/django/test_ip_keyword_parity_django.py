import os
import sys
from unittest.mock import MagicMock, patch

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
os.environ.setdefault("DJANGO_SETTINGS_MODULE", "tests.test_settings")

import django
django.setup()

from tests.django.base_test import AIWAFMiddlewareTestCase
from aiwaf.django.middleware import IPAndKeywordBlockMiddleware


class IPKeywordParityDjangoTestCase(AIWAFMiddlewareTestCase):
    def test_django_keyword_policy_parity_allow_safe_route(self):
        store = MagicMock()
        store.get_top_keywords.return_value = []
        with patch("aiwaf.django.middleware.get_keyword_store", return_value=store), \
             patch("aiwaf.django.middleware.is_middleware_disabled", return_value=False), \
             patch("aiwaf.django.middleware.is_exempt", return_value=False), \
             patch("aiwaf.django.middleware.is_ip_exempted", return_value=False), \
             patch("aiwaf.django.middleware.BlocklistManager.is_blocked", return_value=False), \
             patch("aiwaf.django.middleware.path_exists_in_django", return_value=True):
            middleware = IPAndKeywordBlockMiddleware(self.mock_get_response)
            request = self.factory.get("/safe")
            request.META["REMOTE_ADDR"] = "203.0.113.10"
            response = middleware(request)
        self.assertEqual(response.status_code, 200)

    def test_django_keyword_policy_parity_block_static_malicious_path_requires_rich_context(self):
        store = MagicMock()
        store.get_top_keywords.return_value = []
        with patch("aiwaf.django.middleware.get_keyword_store", return_value=store), \
             patch("aiwaf.django.middleware.is_middleware_disabled", return_value=False), \
             patch("aiwaf.django.middleware.is_exempt", return_value=False), \
             patch("aiwaf.django.middleware.is_ip_exempted", return_value=False), \
             patch("aiwaf.django.middleware.BlocklistManager.block"), \
             patch("aiwaf.django.middleware.BlocklistManager.is_blocked", return_value=False), \
             patch("aiwaf.django.middleware.path_exists_in_django", return_value=False), \
             patch("aiwaf.django.middleware._raise_blocked") as mock_raise:
            middleware = IPAndKeywordBlockMiddleware(self.mock_get_response)
            request = self.factory.get("/admin.php")
            request.META["REMOTE_ADDR"] = "203.0.113.11"
            middleware(request)
        # Django-rich behavior: .php path alone is not guaranteed block without
        # matching suspicious segment/context criteria.
        self.assertFalse(mock_raise.called)

    def test_django_keyword_policy_parity_block_learned_keyword(self):
        store = MagicMock()
        store.get_top_keywords.return_value = ["shellupload"]
        with patch("aiwaf.django.middleware.get_keyword_store", return_value=store), \
             patch("aiwaf.django.middleware.is_middleware_disabled", return_value=False), \
             patch("aiwaf.django.middleware.is_exempt", return_value=False), \
             patch("aiwaf.django.middleware.is_ip_exempted", return_value=False), \
             patch("aiwaf.django.middleware.BlocklistManager.block"), \
             patch("aiwaf.django.middleware.BlocklistManager.is_blocked", side_effect=[False, True]), \
             patch("aiwaf.django.middleware.path_exists_in_django", return_value=False), \
             patch("aiwaf.django.middleware._raise_blocked") as mock_raise:
            middleware = IPAndKeywordBlockMiddleware(self.mock_get_response)
            request = self.factory.get("/shellupload")
            request.META["REMOTE_ADDR"] = "203.0.113.12"
            middleware(request)
        self.assertTrue(mock_raise.called)
