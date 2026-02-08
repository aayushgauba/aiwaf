#!/usr/bin/env python3
"""
Django Unit Test for View Method Detection

Test the enhanced HoneypotTimingMiddleware that checks actual view HTTP methods.
"""

import os
import sys
from unittest.mock import MagicMock, patch

# Setup Django
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
os.environ.setdefault('DJANGO_SETTINGS_MODULE', 'tests.test_settings')

import django
django.setup()

from django.core.cache import cache
from tests.base_test import AIWAFMiddlewareTestCase
from aiwaf.middleware import HoneypotTimingMiddleware


class ViewMethodDetectionTestCase(AIWAFMiddlewareTestCase):
    """Test View Method Detection functionality"""
    
    def setUp(self):
        super().setUp()
        cache.clear()
    
    def test_view_method_detection(self):
        """GET-only views reject POST when method detection can determine it."""
        middleware = HoneypotTimingMiddleware(self.mock_get_response)
        request = self.factory.post("/web/test/", data={"x": "1"}, REMOTE_ADDR="203.0.113.164")
        middleware._view_accepts_method = MagicMock(return_value=False)
        with patch("aiwaf.middleware.is_middleware_disabled", return_value=False), \
             patch("aiwaf.middleware.is_exempt", return_value=False), \
             patch("aiwaf.middleware.is_ip_exempted", return_value=False), \
             patch("aiwaf.middleware.BlacklistManager.block") as mock_block, \
             patch("aiwaf.middleware.BlacklistManager.is_blocked", return_value=True):
            response = middleware.process_request(request)
        self.assertIsNotNone(response)
        self.assertEqual(response.status_code, 405)
        mock_block.assert_called_once()
        
        # Example patterns:
        # request = self.create_request('/test/path/')
        # response = self.process_request_through_middleware(MiddlewareClass, request)
        # self.assertEqual(response.status_code, 200)
    
    def test_security_scenarios(self):
        """Obvious POST-only endpoints can reject GET when detection says GET unsupported."""
        middleware = HoneypotTimingMiddleware(self.mock_get_response)
        request = self.factory.get("/api/create/", REMOTE_ADDR="203.0.113.165")
        middleware._view_accepts_method = MagicMock(return_value=False)
        with patch("aiwaf.middleware.is_middleware_disabled", return_value=False), \
             patch("aiwaf.middleware.is_exempt", return_value=False), \
             patch("aiwaf.middleware.is_ip_exempted", return_value=False), \
             patch("aiwaf.middleware.BlacklistManager.block") as mock_block, \
             patch("aiwaf.middleware.BlacklistManager.is_blocked", return_value=True):
            response = middleware.process_request(request)
        self.assertIsNotNone(response)
        self.assertEqual(response.status_code, 405)
        mock_block.assert_called_once()
        
        # Example patterns:
        # request = self.create_request('/test/path/')
        # response = self.process_request_through_middleware(MiddlewareClass, request)
        # self.assertEqual(response.status_code, 200)
    
    def test_middleware_logic(self):
        """GET requests store a honeypot timestamp for later POST timing checks."""
        middleware = HoneypotTimingMiddleware(self.mock_get_response)
        request = self.factory.get("/web/form/", REMOTE_ADDR="203.0.113.166")
        middleware._view_accepts_method = MagicMock(return_value=True)

        with patch("aiwaf.middleware.is_middleware_disabled", return_value=False), \
             patch("aiwaf.middleware.is_exempt", return_value=False), \
             patch("aiwaf.middleware.is_ip_exempted", return_value=False):
            response = middleware.process_request(request)
        self.assertIsNone(response)
        self.assertIsNotNone(cache.get("honeypot_get:203.0.113.166"))
        
        # Example patterns:
        # request = self.create_request('/test/path/')
        # response = self.process_request_through_middleware(MiddlewareClass, request)
        # self.assertEqual(response.status_code, 200)
    


if __name__ == "__main__":
    import unittest
    unittest.main()
