#!/usr/bin/env python3
"""
Django Unit Test for Simplified Honeypot

Test that the middleware works correctly after removing direct POST without GET detection

This test verifies:
1. Method validation still works
2. Timing validation still works 
3. No blocking for direct POST (only method validation applies)
"""

import os
import sys
import types
from unittest.mock import MagicMock, patch

# Setup Django
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
os.environ.setdefault('DJANGO_SETTINGS_MODULE', 'tests.test_settings')

import django
django.setup()

from django.core.cache import cache
from tests.base_test import AIWAFMiddlewareTestCase
from aiwaf.middleware import HoneypotTimingMiddleware


class SimplifiedHoneypotTestCase(AIWAFMiddlewareTestCase):
    """Test Simplified Honeypot functionality"""
    
    def setUp(self):
        super().setUp()
        cache.clear()
    
    def test_simplified_honeypot(self):
        """
        Direct POST without a preceding GET is not blocked by timing rules.

        Only method validation should apply; if the view accepts POST, we allow it.
        """
        middleware = HoneypotTimingMiddleware(self.mock_get_response)
        middleware._view_accepts_method = MagicMock(return_value=True)

        request = self.factory.post("/web/form/", data={"x": "1"}, REMOTE_ADDR="203.0.113.175")
        with patch("aiwaf.middleware.is_middleware_disabled", return_value=False), \
             patch("aiwaf.middleware.is_exempt", return_value=False), \
             patch("aiwaf.middleware.is_ip_exempted", return_value=False), \
             patch("aiwaf.middleware.BlacklistManager.block") as mock_block:
            response = middleware.process_request(request)

        self.assertIsNone(response)
        mock_block.assert_not_called()

        # Timing validation still works when a GET was recorded.
        ip = "203.0.113.176"
        cache.set(f"honeypot_get:{ip}", 1000.0, timeout=300)
        fast_post = self.factory.post("/web/form/", data={"x": "1"}, REMOTE_ADDR=ip)

        ticks = iter([1000.05, 1000.05])  # time.time() and get_time check
        fake_time = types.SimpleNamespace(time=lambda: next(ticks))
        with patch("aiwaf.middleware.time", new=fake_time), \
             patch("aiwaf.middleware.is_middleware_disabled", return_value=False), \
             patch("aiwaf.middleware.is_exempt", return_value=False), \
             patch("aiwaf.middleware.is_ip_exempted", return_value=False), \
             patch("aiwaf.middleware.BlacklistManager.block") as mock_block, \
             patch("aiwaf.middleware.BlacklistManager.is_blocked", return_value=True), \
             patch("aiwaf.middleware._raise_blocked") as mock_raise:
            middleware.process_request(fast_post)

        mock_block.assert_called_once()
        mock_raise.assert_called_once()
        
        # Example patterns:
        # request = self.create_request('/test/path/')
        # response = self.process_request_through_middleware(MiddlewareClass, request)
        # self.assertEqual(response.status_code, 200)
    


if __name__ == "__main__":
    import unittest
    unittest.main()
