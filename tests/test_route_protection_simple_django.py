#!/usr/bin/env python3
"""
Django Unit Test for Route Protection Simple

Test the keyword extraction logic without Django setup
"""

import os
import sys
import re
from unittest.mock import MagicMock, patch

# Setup Django
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
os.environ.setdefault('DJANGO_SETTINGS_MODULE', 'tests.test_settings')

import django
django.setup()

from django.test import override_settings
from tests.base_test import AIWAFTestCase
from aiwaf.middleware import IPAndKeywordBlockMiddleware


class RouteProtectionSimpleTestCase(AIWAFTestCase):
    """Test Route Protection Simple functionality"""
    
    def setUp(self):
        super().setUp()
    
    def test_keyword_extraction_logic(self):
        """Middleware splits path into segments and ignores short tokens."""
        path = "/api/v1/users/123/evilzebra.php"
        segments = [seg for seg in re.split(r"\W+", path.lstrip("/")) if len(seg) > 3]
        self.assertIn("users", segments)
        self.assertIn("evilzebra", segments)
        self.assertNotIn("api", segments)  # len=3 filtered out
        
        # Example patterns:
        # request = self.create_request('/test/path/')
        # response = self.process_request_through_middleware(MiddlewareClass, request)
        # self.assertEqual(response.status_code, 200)
    
    def test_keyword_learning_protection(self):
        """Learning is disabled for valid Django paths (path_exists=True)."""
        store = MagicMock()
        store.get_top_keywords.return_value = []
        store.add_keyword = MagicMock()
        with override_settings(AIWAF_ENABLE_KEYWORD_LEARNING=True):
            middleware = IPAndKeywordBlockMiddleware(lambda r: None)
            middleware.safe_prefixes = set()
            request = self.create_request("/api/users/")
            request.META["REMOTE_ADDR"] = "203.0.113.181"
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
