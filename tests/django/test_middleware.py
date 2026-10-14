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
from tests.django.base_test import AIWAFMiddlewareTestCase
from aiwaf.django.middleware import IPAndKeywordBlockMiddleware
from aiwaf.django import middleware as middleware_module
from django.http import HttpResponse
from django.test import RequestFactory


class MiddlewareProtectionTestCase(AIWAFMiddlewareTestCase):
    """Test Middleware Protection functionality"""
    
    def setUp(self):
        super().setUp()
        self.middleware = IPAndKeywordBlockMiddleware(self.mock_get_response)

    def test_compatibility_and_validation_helpers(self):
        json_middleware = middleware_module.JsonExceptionMiddleware(lambda _request: HttpResponse("ok"))
        request = self.factory.get("/")
        self.assertEqual(json_middleware(request).status_code, 200)
        self.assertEqual(middleware_module._get_uuid_model_fields("missing-aiwaf-app"), [])

        fallback = self.middleware._get_legitimate_keywords_fallback()
        self.assertIn("login", fallback)
        self.assertTrue(self.middleware._extract_django_route_keywords())

        header = middleware_module.HeaderValidationMiddleware(lambda _request: HttpResponse("ok"))
        self.assertEqual(header._check_missing_headers({}, ["HTTP_ACCEPT"]), ["accept"])
        self.assertEqual(header._check_user_agent(""), "Empty user agent")
        self.assertIsNone(header._check_user_agent("Mozilla/5.0 normal browser"))
        self.assertTrue(header._is_http_meta_key("HTTP_ACCEPT"))
        self.assertIsNone(header._enforce_header_caps({"HTTP_ACCEPT": "text/html"}))
        self.assertIsNotNone(
            header._check_header_combinations({"HTTP_USER_AGENT": "browser"}, ["HTTP_ACCEPT"])
        )
        self.assertGreater(
            header._calculate_header_quality(
                {"HTTP_USER_AGENT": "browser", "HTTP_ACCEPT": "text/html,application/xml"}
            ),
            0,
        )

        anomaly = middleware_module.AIAnomalyMiddleware.__new__(middleware_module.AIAnomalyMiddleware)
        anomaly.malicious_keywords = set()
        self.assertEqual(anomaly._count_log_lines("missing.log", 2), 0)
        stats = anomaly._analyze_recent_behavior_python([])
        self.assertEqual(stats["total_requests"], 0)
    
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
        
        with patch("aiwaf.django.middleware.get_keyword_store", return_value=store), \
             patch("aiwaf.django.middleware.is_middleware_disabled", return_value=False), \
             patch("aiwaf.django.middleware.is_exempt", return_value=False), \
             patch("aiwaf.django.middleware.is_ip_exempted", return_value=False), \
             patch("aiwaf.django.middleware.BlocklistManager.is_blocked", return_value=False), \
             patch("aiwaf.django.middleware.BlocklistManager.block"), \
             patch("aiwaf.django.middleware.path_exists_in_django", return_value=False), \
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
        
        with patch("aiwaf.django.middleware.get_keyword_store", return_value=store), \
             patch("aiwaf.django.middleware.is_middleware_disabled", return_value=False), \
             patch("aiwaf.django.middleware.is_exempt", return_value=False), \
             patch("aiwaf.django.middleware.is_ip_exempted", return_value=False), \
             patch("aiwaf.django.middleware.BlocklistManager.is_blocked", return_value=False), \
             patch("aiwaf.django.middleware.BlocklistManager.block") as mock_block, \
             patch("aiwaf.django.middleware.path_exists_in_django", return_value=True):
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
        
        with patch("aiwaf.django.middleware.get_keyword_store", return_value=store), \
             patch("aiwaf.django.middleware.is_middleware_disabled", return_value=False), \
             patch("aiwaf.django.middleware.is_exempt", return_value=False), \
             patch("aiwaf.django.middleware.is_ip_exempted", return_value=False), \
             patch("aiwaf.django.middleware.BlocklistManager.is_blocked", side_effect=[False, True]), \
             patch("aiwaf.django.middleware.BlocklistManager.block") as mock_block, \
             patch("aiwaf.django.middleware._get_blocklist_extended_info", return_value=None), \
             patch("aiwaf.django.middleware.path_exists_in_django", return_value=False), \
             patch("aiwaf.django.middleware._raise_blocked") as mock_raise:
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
