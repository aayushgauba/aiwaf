#!/usr/bin/env python3
"""
Django Unit Test for Middleware Protection

Django Unit Test for Middleware Route Protection

Tests middleware route protection functionality including:
1. Legitimate keyword detection
2. Route-based protection logic
3. Keyword filtering and validation
4. Integration with trainer system
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


class MiddlewareProtectionTestCase(AIWAFMiddlewareTestCase):
    """Test Middleware Protection functionality"""
    
    def setUp(self):
        super().setUp()
        self.middleware = IPAndKeywordBlockMiddleware(self.mock_get_response)
    
    def test_middleware_legitimate_keyword_detection(self):
        """Default legitimate keyword list includes common routes like 'login'."""
        self.assertIn("login", self.middleware.legitimate_path_keywords)
        self.assertIn("profile", self.middleware.legitimate_path_keywords)
    
    @override_settings(AIWAF_ENABLE_KEYWORD_LEARNING=True)
    def test_middleware_keyword_extraction(self):
        """Unknown keywords learned only from suspicious contexts."""
        store = MagicMock()
        store.get_top_keywords.return_value = []
        store.add_keyword = MagicMock()
        
        with patch("aiwaf.middleware.get_keyword_store", return_value=store), \
             patch("aiwaf.middleware.is_middleware_disabled", return_value=False), \
             patch("aiwaf.middleware.is_exempt", return_value=False), \
             patch("aiwaf.middleware.is_ip_exempted", return_value=False), \
             patch("aiwaf.middleware.BlacklistManager.is_blocked", return_value=False), \
             patch("aiwaf.middleware.BlacklistManager.block"), \
             patch("aiwaf.middleware.path_exists_in_django", return_value=False), \
             patch.object(IPAndKeywordBlockMiddleware, "_is_malicious_context") as ctx_mock:
            call_state = {"first": True}

            def fake_is_malicious(req, segment):
                if call_state["first"]:
                    call_state["first"] = False
                    return True
                return False

            ctx_mock.side_effect = fake_is_malicious
            middleware = IPAndKeywordBlockMiddleware(self.mock_get_response)
            request = self.factory.get("/shellupload/?payload=1")
            request.META["REMOTE_ADDR"] = "203.0.113.200"
            middleware(request)
        
        store.add_keyword.assert_called_with("shellupload")
    
    @override_settings(AIWAF_ENABLE_KEYWORD_LEARNING=True)
    def test_middleware_route_learning_integration(self):
        """Legitimate paths with known keywords should not trigger blocking."""
        store = MagicMock()
        store.get_top_keywords.return_value = []
        
        with patch("aiwaf.middleware.get_keyword_store", return_value=store), \
             patch("aiwaf.middleware.is_middleware_disabled", return_value=False), \
             patch("aiwaf.middleware.is_exempt", return_value=False), \
             patch("aiwaf.middleware.is_ip_exempted", return_value=False), \
             patch("aiwaf.middleware.BlacklistManager.is_blocked", return_value=False), \
             patch("aiwaf.middleware.BlacklistManager.block") as mock_block, \
             patch("aiwaf.middleware.path_exists_in_django", return_value=True):
            middleware = IPAndKeywordBlockMiddleware(self.mock_get_response)
            request = self.factory.get("/profile/settings/")
            request.META["REMOTE_ADDR"] = "203.0.113.201"
            middleware(request)
        
        mock_block.assert_not_called()
    
    @override_settings(AIWAF_ENABLE_KEYWORD_LEARNING=True, AIWAF_DYNAMIC_TOP_N=5)
    def test_middleware_filtering_blocks_suspicious_keyword(self):
        """Dynamic suspicious keywords trigger blocking for nonexistent paths."""
        store = MagicMock()
        store.get_top_keywords.return_value = ["shellupload"]
        
        with patch("aiwaf.middleware.get_keyword_store", return_value=store), \
             patch("aiwaf.middleware.is_middleware_disabled", return_value=False), \
             patch("aiwaf.middleware.is_exempt", return_value=False), \
             patch("aiwaf.middleware.is_ip_exempted", return_value=False), \
             patch("aiwaf.middleware.BlacklistManager.is_blocked", side_effect=[False, True]), \
             patch("aiwaf.middleware.BlacklistManager.block") as mock_block, \
             patch("aiwaf.middleware._get_blacklist_extended_info", return_value=None), \
             patch("aiwaf.middleware.path_exists_in_django", return_value=False), \
             patch("aiwaf.middleware._raise_blocked") as mock_raise:
            middleware = IPAndKeywordBlockMiddleware(self.mock_get_response)
            request = self.factory.get("/shellupload/")
            request.META["REMOTE_ADDR"] = "203.0.113.202"
            middleware(request)
        
        mock_block.assert_called_once()
        args, _ = mock_raise.call_args
        self.assertIn("Keyword block", args[1])
        self.assertIn("shellupload", args[1])
    


if __name__ == "__main__":
    import unittest
    unittest.main()
