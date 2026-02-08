#!/usr/bin/env python3
"""
Django Unit Test for Keyword Protection

AIWAF Keyword Protection Test Script

This script demonstrates the new keyword filtering functionality 
that prevents legitimate paths like /en/profile/ from being blocked.

Run this test after configuring AIWAF_ALLOWED_PATH_KEYWORDS in your settings.
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


class KeywordProtectionTestCase(AIWAFMiddlewareTestCase):
    """Test Keyword Protection functionality"""
    
    def setUp(self):
        super().setUp()
        store = get_keyword_store()
        for kw in store.get_all_keywords():
            store.remove_keyword(kw)
    
    def test_keyword_filtering(self):
        """Legitimate path keywords should not trigger blocks on valid paths."""
        store = get_keyword_store()
        store.add_keyword("profile", 10)  # learned keyword colliding with legitimate route segment

        with override_settings(AIWAF_ENABLE_KEYWORD_LEARNING=True):
            middleware = IPAndKeywordBlockMiddleware(MagicMock(return_value=MagicMock(status_code=200)))
            middleware.safe_prefixes = set()
            request = self.factory.get("/en/profile/")
            request.META["REMOTE_ADDR"] = "203.0.113.230"
            with patch("aiwaf.middleware.is_middleware_disabled", return_value=False), \
                 patch("aiwaf.middleware.is_exempt", return_value=False), \
                 patch("aiwaf.middleware.is_ip_exempted", return_value=False), \
                 patch("aiwaf.middleware.BlacklistManager.is_blocked", return_value=False), \
                 patch("aiwaf.middleware.path_exists_in_django", return_value=True), \
                 patch("aiwaf.middleware.BlacklistManager.block") as mock_block:
                middleware(request)

        mock_block.assert_not_called()
        
        # Example patterns:
        # request = self.create_request('/test/path/')
        # response = self.process_request_through_middleware(MiddlewareClass, request)
        # self.assertEqual(response.status_code, 200)
    
    def test_profile_scenario(self):
        """Allowed path keywords can be configured to avoid accidental blocks."""
        store = get_keyword_store()
        store.add_keyword("evilzebra", 10)

        with override_settings(AIWAF_ALLOWED_PATH_KEYWORDS=["evilzebra"]):
            middleware = IPAndKeywordBlockMiddleware(MagicMock(return_value=MagicMock(status_code=200)))
            middleware.safe_prefixes = set()
            request = self.factory.get("/en/evilzebra/")
            request.META["REMOTE_ADDR"] = "203.0.113.231"
            with patch("aiwaf.middleware.is_middleware_disabled", return_value=False), \
                 patch("aiwaf.middleware.is_exempt", return_value=False), \
                 patch("aiwaf.middleware.is_ip_exempted", return_value=False), \
                 patch("aiwaf.middleware.BlacklistManager.is_blocked", return_value=False), \
                 patch("aiwaf.middleware.path_exists_in_django", return_value=True), \
                 patch("aiwaf.middleware.BlacklistManager.block") as mock_block:
                middleware(request)

        mock_block.assert_not_called()
        
        # Example patterns:
        # request = self.create_request('/test/path/')
        # response = self.process_request_through_middleware(MiddlewareClass, request)
        # self.assertEqual(response.status_code, 200)
    


if __name__ == "__main__":
    import unittest
    unittest.main()
