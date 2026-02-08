#!/usr/bin/env python3
"""
Django Unit Test for Method Validation Simple

Test HTTP method validation logic in HoneypotTimingMiddleware

This test verifies the _view_accepts_method function works correctly
for different view types and method combinations.
"""

import os
import sys
from unittest.mock import patch, MagicMock

# Setup Django
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
os.environ.setdefault('DJANGO_SETTINGS_MODULE', 'tests.test_settings')

import django
django.setup()

from tests.base_test import AIWAFMiddlewareTestCase
from aiwaf.middleware import HoneypotTimingMiddleware


class MethodValidationSimpleTestCase(AIWAFMiddlewareTestCase):
    """Test Method Validation Simple functionality"""
    
    def setUp(self):
        super().setUp()
    
    def test_view_accepts_method(self):
        """_view_accepts_method uses resolver and is permissive on failure."""
        middleware = HoneypotTimingMiddleware(self.mock_get_response)

        # When resolve fails, method detection must be permissive.
        req = self.create_request("/anything/")
        with patch("django.urls.resolve", side_effect=Exception("boom")):
            self.assertTrue(middleware._view_accepts_method(req, "GET"))
            self.assertTrue(middleware._view_accepts_method(req, "POST"))
        
        # Example patterns:
        # request = self.create_request('/test/path/')
        # response = self.process_request_through_middleware(MiddlewareClass, request)
        # self.assertEqual(response.status_code, 200)
    
    def test_middleware_integration(self):
        """process_request uses method detection for POST requests."""
        middleware = HoneypotTimingMiddleware(self.mock_get_response)
        request = self.factory.post("/web/test/", data={"x": "1"}, REMOTE_ADDR="203.0.113.163")

        # Force method detection to say POST is not accepted.
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
    


if __name__ == "__main__":
    import unittest
    unittest.main()
