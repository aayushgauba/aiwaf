#!/usr/bin/env python3
"""
Django Unit Test for Rate Limiting

Test script to verify AIWAF rate limiting works correctly.
This script simulates burst requests to test the RateLimitMiddleware.
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

from django.core.exceptions import PermissionDenied
from django.test import override_settings
from tests.base_test import AIWAFMiddlewareTestCase
from aiwaf.middleware import RateLimitMiddleware


class RateLimitingTestCase(AIWAFMiddlewareTestCase):
    """Test Rate Limiting functionality"""
    
    def setUp(self):
        super().setUp()
        from django.core.cache import cache
        cache.clear()
    
    @override_settings(AIWAF_RATE_WINDOW=10, AIWAF_RATE_MAX=3, AIWAF_RATE_FLOOD=5)
    def test_rate_limiting(self):
        """Flood threshold triggers a block and raises PermissionDenied."""
        request = self.create_request("/rl/", headers={"REMOTE_ADDR": "203.0.113.250"})
        middleware = RateLimitMiddleware(self.mock_get_response)
        ticks = iter([0, 1, 2, 3, 4, 5])
        fake_time = types.SimpleNamespace(time=lambda: next(ticks))

        with patch("aiwaf.middleware.is_middleware_disabled", return_value=False), \
             patch("aiwaf.middleware.is_exempt", return_value=False), \
             patch("aiwaf.middleware.is_ip_exempted", return_value=False), \
             patch("aiwaf.middleware.get_rate_limit_overrides", return_value={}), \
             patch("aiwaf.middleware.BlacklistManager.block") as mock_block, \
             patch("aiwaf.middleware.BlacklistManager.is_blocked", return_value=True), \
             patch("aiwaf.middleware.time", new=fake_time):
            # First 5 requests are allowed; the 6th exceeds flood=5 and blocks.
            for _ in range(5):
                resp = middleware(request)
                self.assertIsNotNone(resp)
            with self.assertRaises(PermissionDenied):
                middleware(request)
        mock_block.assert_called_once()
    


if __name__ == "__main__":
    import unittest
    unittest.main()
