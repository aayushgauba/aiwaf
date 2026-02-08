#!/usr/bin/env python3
"""
Django Unit Test for Route Keyword Extraction

Test that Django route keywords are properly extracted and ignored
"""

import os
import sys
from contextlib import ExitStack
from unittest.mock import MagicMock, patch

# Setup Django
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
os.environ.setdefault('DJANGO_SETTINGS_MODULE', 'tests.test_settings')

import django
django.setup()

from django.test import override_settings
from tests.base_test import AIWAFTrainerTestCase
from aiwaf.trainer import get_legitimate_keywords
from aiwaf.middleware import IPAndKeywordBlockMiddleware


class RouteKeywordExtractionTestCase(AIWAFTrainerTestCase):
    """Test Route Keyword Extraction functionality"""
    
    def setUp(self):
        super().setUp()
    
    def _make_keyword_store(self):
        store = MagicMock()
        store.get_top_keywords.return_value = []
        store.add_keyword = MagicMock()
        return store
    
    def _patch_learning_deps(self, store, path_exists):
        stack = ExitStack()
        stack.enter_context(patch("aiwaf.middleware.get_keyword_store", return_value=store))
        stack.enter_context(patch("aiwaf.middleware.is_middleware_disabled", return_value=False))
        stack.enter_context(patch("aiwaf.middleware.is_exempt", return_value=False))
        stack.enter_context(patch("aiwaf.middleware.is_ip_exempted", return_value=False))
        stack.enter_context(patch("aiwaf.middleware.BlacklistManager.is_blocked", return_value=False))
        stack.enter_context(patch("aiwaf.middleware.path_exists_in_django", return_value=path_exists))
        return stack
    
    def test_route_keyword_extraction(self):
        """Route keywords from Django URLconf are treated as legitimate."""
        kws = get_legitimate_keywords()
        # From tests.test_urls: /api/users/
        self.assertIn("api", kws)
        self.assertIn("users", kws)
        self.assertIn("admin", kws)
        
        # Example patterns:
        # request = self.create_request('/test/path/')
        # response = self.process_request_through_middleware(MiddlewareClass, request)
        # self.assertEqual(response.status_code, 200)
    
    def test_keyword_learning_with_routes(self):
        """Middleware does not learn keywords from paths that exist in Django."""
        store = self._make_keyword_store()
        with override_settings(AIWAF_ENABLE_KEYWORD_LEARNING=True):
            middleware = IPAndKeywordBlockMiddleware(lambda r: None)
            middleware.safe_prefixes = set()
            request = self.create_request("/api/users/")
            request.META["REMOTE_ADDR"] = "203.0.113.180"
            with self._patch_learning_deps(store, path_exists=True) as st:
                middleware(request)
        store.add_keyword.assert_not_called()
        
        # Example patterns:
        # request = self.create_request('/test/path/')
        # response = self.process_request_through_middleware(MiddlewareClass, request)
        # self.assertEqual(response.status_code, 200)
    


if __name__ == "__main__":
    import unittest
    unittest.main()
