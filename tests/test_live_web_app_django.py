#!/usr/bin/env python3
"""
Django Unit Test for Live Web App

Live Web App Test for AIWAF Keyword Storage
Use this script to test keyword learning on a running web application.
This can be used with curl, requests, or any HTTP client.
"""

import os
import sys
from unittest.mock import MagicMock, patch

# Setup Django
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
os.environ.setdefault('DJANGO_SETTINGS_MODULE', 'tests.test_settings')

import django
django.setup()

from django.test import override_settings
from tests.base_test import AIWAFMiddlewareTestCase
from aiwaf.middleware import IPAndKeywordBlockMiddleware
from aiwaf.storage import get_keyword_store


class LiveWebAppTestCase(AIWAFMiddlewareTestCase):
    """Test Live Web App functionality"""
    
    def setUp(self):
        super().setUp()
        store = get_keyword_store()
        for kw in store.get_all_keywords():
            store.remove_keyword(kw)
    
    def test_malicious_requests(self):
        """Non-existent attack paths should cause keyword learning."""
        store = get_keyword_store()
        middleware = IPAndKeywordBlockMiddleware(MagicMock(return_value=MagicMock(status_code=200)))
        middleware.safe_prefixes = set()

        with override_settings(AIWAF_ENABLE_KEYWORD_LEARNING=True):
            request = self.factory.get("/wp-admin/evilzebra.php")
            request.META["REMOTE_ADDR"] = "203.0.113.240"
            with patch("aiwaf.middleware.is_middleware_disabled", return_value=False), \
                 patch("aiwaf.middleware.is_exempt", return_value=False), \
                 patch("aiwaf.middleware.is_ip_exempted", return_value=False), \
                 patch("aiwaf.middleware.BlacklistManager.is_blocked", return_value=False), \
                 patch("aiwaf.middleware.path_exists_in_django", return_value=False), \
                 patch.object(IPAndKeywordBlockMiddleware, "_is_malicious_context", return_value=True):
                middleware(request)

        self.assertTrue(list(store.get_all_keywords()))
        
        # Example patterns:
        # request = self.create_request('/test/path/')
        # response = self.process_request_through_middleware(MiddlewareClass, request)
        # self.assertEqual(response.status_code, 200)
    
    def test_legitimate_requests(self):
        """Existing Django routes should not cause keyword learning."""
        store = get_keyword_store()
        middleware = IPAndKeywordBlockMiddleware(MagicMock(return_value=MagicMock(status_code=200)))
        middleware.safe_prefixes = set()

        with override_settings(AIWAF_ENABLE_KEYWORD_LEARNING=True):
            request = self.factory.get("/api/users/")
            request.META["REMOTE_ADDR"] = "203.0.113.241"
            with patch("aiwaf.middleware.is_middleware_disabled", return_value=False), \
                 patch("aiwaf.middleware.is_exempt", return_value=False), \
                 patch("aiwaf.middleware.is_ip_exempted", return_value=False), \
                 patch("aiwaf.middleware.BlacklistManager.is_blocked", return_value=False), \
                 patch("aiwaf.middleware.path_exists_in_django", return_value=True), \
                 patch.object(IPAndKeywordBlockMiddleware, "_is_malicious_context", return_value=True):
                middleware(request)

        self.assertEqual(list(store.get_all_keywords()), [])
        
        # Example patterns:
        # request = self.create_request('/test/path/')
        # response = self.process_request_through_middleware(MiddlewareClass, request)
        # self.assertEqual(response.status_code, 200)
    


if __name__ == "__main__":
    import unittest
    unittest.main()
