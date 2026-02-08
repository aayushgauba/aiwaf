#!/usr/bin/env python3
"""
Django Unit Test for Storage Fix

Test script to demonstrate the keyword storage persistence fix.
This simulates the middleware behavior without requiring Django.
"""

import os
import sys
from unittest.mock import patch, MagicMock

# Setup Django
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
os.environ.setdefault('DJANGO_SETTINGS_MODULE', 'tests.test_settings')

import django
django.setup()

from django.core.cache import cache
from tests.base_test import AIWAFStorageTestCase
from aiwaf.storage import get_keyword_store
from aiwaf.middleware import IPAndKeywordBlockMiddleware


class StorageFixTestCase(AIWAFStorageTestCase):
    """Test Storage Fix functionality"""
    
    def setUp(self):
        super().setUp()
        cache.clear()
    
    def test_keyword_storage_without_django(self):
        """Keyword store add/remove/top APIs work (DB-backed in Django tests)."""
        store = get_keyword_store()
        # Ensure clean slate
        for kw in store.get_all_keywords():
            store.remove_keyword(kw)

        store.add_keyword("gamma", 2)
        store.add_keyword("delta", 1)
        self.assertIn("gamma", list(store.get_all_keywords()))
        self.assertEqual(store.get_top_keywords(1)[0], "gamma")
        store.remove_keyword("gamma")
        self.assertNotIn("gamma", list(store.get_all_keywords()))
        
        # Example patterns:
        # request = self.create_request('/test/path/')
        # response = self.process_request_through_middleware(MiddlewareClass, request)
        # self.assertEqual(response.status_code, 200)
    
    def test_middleware_integration(self):
        """Middleware learns keywords and they show up in the store."""
        store = get_keyword_store()
        for kw in store.get_all_keywords():
            store.remove_keyword(kw)

        middleware = IPAndKeywordBlockMiddleware(MagicMock(return_value=MagicMock(status_code=200)))
        middleware.safe_prefixes = set()

        request = self.factory.get("/nope/evilzebra.php")
        request.META["REMOTE_ADDR"] = "203.0.113.77"

        with patch("aiwaf.middleware.is_middleware_disabled", return_value=False), \
             patch("aiwaf.middleware.is_exempt", return_value=False), \
             patch("aiwaf.middleware.is_ip_exempted", return_value=False), \
             patch("aiwaf.middleware.BlacklistManager.is_blocked", return_value=False), \
             patch("aiwaf.middleware.path_exists_in_django", return_value=False), \
             patch.object(IPAndKeywordBlockMiddleware, "_is_malicious_context", return_value=True):
            middleware(request)

        all_kws = list(store.get_all_keywords())
        self.assertTrue(all_kws)
        
        # Example patterns:
        # request = self.create_request('/test/path/')
        # response = self.process_request_through_middleware(MiddlewareClass, request)
        # self.assertEqual(response.status_code, 200)
    


if __name__ == "__main__":
    import unittest
    unittest.main()
