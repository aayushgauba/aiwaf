#!/usr/bin/env python3
"""
Django Unit Test for Middleware Learning Fix

Test to demonstrate the middleware learning behavior and the fix for learning from all requests.
"""

import os
import sys
from unittest.mock import patch, MagicMock

# Setup Django
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
os.environ.setdefault('DJANGO_SETTINGS_MODULE', 'tests.test_settings')

import django
django.setup()

from django.test import override_settings
from tests.base_test import AIWAFMiddlewareTestCase
from aiwaf.middleware import IPAndKeywordBlockMiddleware


class MiddlewareLearningFixTestCase(AIWAFMiddlewareTestCase):
    """Test Middleware Learning Fix functionality"""
    
    def setUp(self):
        super().setUp()
    
    def test_middleware_learning_logic(self):
        """Learns only from non-existent paths in malicious context."""
        store = MagicMock()
        store.get_top_keywords.return_value = []
        store.add_keyword = MagicMock()

        with override_settings(AIWAF_ENABLE_KEYWORD_LEARNING=True):
            middleware = IPAndKeywordBlockMiddleware(self.mock_get_response)
            middleware.safe_prefixes = set()
            request = self.factory.get("/nope/evilzebra.php")
            request.META["REMOTE_ADDR"] = "203.0.113.140"
            with patch("aiwaf.middleware.get_keyword_store", return_value=store), \
                 patch("aiwaf.middleware.is_middleware_disabled", return_value=False), \
                 patch("aiwaf.middleware.is_exempt", return_value=False), \
                 patch("aiwaf.middleware.is_ip_exempted", return_value=False), \
                 patch("aiwaf.middleware.BlacklistManager.is_blocked", return_value=False), \
                 patch("aiwaf.middleware.path_exists_in_django", return_value=False), \
                 patch.object(IPAndKeywordBlockMiddleware, "_is_malicious_context", return_value=True):
                middleware(request)

        store.add_keyword.assert_called()
        
        # Example patterns:
        # request = self.create_request('/test/path/')
        # response = self.process_request_through_middleware(MiddlewareClass, request)
        # self.assertEqual(response.status_code, 200)
    
    def test_specific_learning_cases(self):
        """Does not learn from valid Django paths even if context looks malicious."""
        store = MagicMock()
        store.get_top_keywords.return_value = []
        store.add_keyword = MagicMock()

        with override_settings(AIWAF_ENABLE_KEYWORD_LEARNING=True):
            middleware = IPAndKeywordBlockMiddleware(self.mock_get_response)
            middleware.safe_prefixes = set()
            request = self.factory.get("/api/users/")
            request.META["REMOTE_ADDR"] = "203.0.113.141"
            with patch("aiwaf.middleware.get_keyword_store", return_value=store), \
                 patch("aiwaf.middleware.is_middleware_disabled", return_value=False), \
                 patch("aiwaf.middleware.is_exempt", return_value=False), \
                 patch("aiwaf.middleware.is_ip_exempted", return_value=False), \
                 patch("aiwaf.middleware.BlacklistManager.is_blocked", return_value=False), \
                 patch("aiwaf.middleware.path_exists_in_django", return_value=True), \
                 patch.object(IPAndKeywordBlockMiddleware, "_is_malicious_context", return_value=True):
                middleware(request)

        store.add_keyword.assert_not_called()
        
        # Example patterns:
        # request = self.create_request('/test/path/')
        # response = self.process_request_through_middleware(MiddlewareClass, request)
        # self.assertEqual(response.status_code, 200)
    


if __name__ == "__main__":
    import unittest
    unittest.main()
