#!/usr/bin/env python3
"""
Django Unit Test for Keyword Storage Debug

Debug test to check if keyword storage works in different phases of middleware processing.
This will test if Django models are available during process_request vs process_response.
"""

import os
import sys
from unittest.mock import patch, MagicMock

# Setup Django
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
os.environ.setdefault('DJANGO_SETTINGS_MODULE', 'tests.test_settings')

import django
django.setup()

from tests.base_test import AIWAFStorageTestCase
from aiwaf.storage import get_keyword_store
from aiwaf.middleware import IPAndKeywordBlockMiddleware


class KeywordStorageDebugTestCase(AIWAFStorageTestCase):
    """Test Keyword Storage Debug functionality"""
    
    def setUp(self):
        super().setUp()
        store = get_keyword_store()
        for kw in store.get_all_keywords():
            store.remove_keyword(kw)
    
    def test_keyword_storage_access(self):
        """Keyword store is available and DB-backed in Django tests."""
        store = get_keyword_store()
        store.add_keyword("debugkw", 1)
        self.assertIn("debugkw", list(store.get_all_keywords()))
        self.assertIn("debugkw", store.get_top_keywords(5))
        
        # Example patterns:
        # request = self.create_request('/test/path/')
        # response = self.process_request_through_middleware(MiddlewareClass, request)
        # self.assertEqual(response.status_code, 200)
    
    def test_middleware_learning_conditions(self):
        """Middleware learning happens in __call__ path when conditions are met."""
        store = get_keyword_store()
        middleware = IPAndKeywordBlockMiddleware(MagicMock(return_value=MagicMock(status_code=200)))
        middleware.safe_prefixes = set()

        request = self.factory.get("/nope/evilzebra.php")
        request.META["REMOTE_ADDR"] = "203.0.113.232"

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
    


if __name__ == "__main__":
    import unittest
    unittest.main()
