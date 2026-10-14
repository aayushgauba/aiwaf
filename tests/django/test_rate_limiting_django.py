#!/usr/bin/env python3
"""
Django Unit Test for Rate Limiting

Test script to verify AIWAF rate limiting works correctly.
This script simulates burst requests to test the RateLimitMiddleware.
"""

import os
import sys
import types
from django.http import JsonResponse
from unittest.mock import MagicMock, patch

# Setup Django
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
os.environ.setdefault('DJANGO_SETTINGS_MODULE', 'tests.test_settings')

import django
django.setup()

from django.core.exceptions import PermissionDenied
from django.test import override_settings
from tests.django.base_test import AIWAFMiddlewareTestCase
from aiwaf.django.middleware import RateLimitMiddleware


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

        with patch("aiwaf.django.middleware.is_middleware_disabled", return_value=False), \
             patch("aiwaf.django.middleware.is_exempt", return_value=False), \
             patch("aiwaf.django.middleware.is_ip_exempted", return_value=False), \
             patch("aiwaf.django.middleware.get_rate_limit_overrides", return_value={}), \
             patch("aiwaf.django.middleware.BlocklistManager.block") as mock_block, \
             patch("aiwaf.django.middleware.BlocklistManager.is_blocked", return_value=True), \
             patch("aiwaf.django.middleware.time", new=fake_time):
            # First 5 requests are allowed; the 6th exceeds flood=5 and blocks.
            for _ in range(5):
                resp = middleware(request)
                self.assertIsNotNone(resp)
            with self.assertRaises(PermissionDenied):
                middleware(request)
        mock_block.assert_called_once()

    @override_settings(
        AIWAF_RATE_WINDOW=10,
        AIWAF_RATE_MAX=1,
        AIWAF_RATE_FLOOD=100,
        AIWAF_RATE_SOFT_BLOCK_BLOCKLIST=False,
    )
    def test_soft_limit_default_does_not_blocklist(self):
        """Default behavior: 429 on soft limit without blocklisting."""
        request = self.create_request("/rl-soft-default/", headers={"REMOTE_ADDR": "203.0.113.210"})
        middleware = RateLimitMiddleware(self.mock_get_response)
        ticks = iter([0, 1])
        fake_time = types.SimpleNamespace(time=lambda: next(ticks))

        with patch("aiwaf.django.middleware.is_middleware_disabled", return_value=False), \
             patch("aiwaf.django.middleware.is_exempt", return_value=False), \
             patch("aiwaf.django.middleware.is_ip_exempted", return_value=False), \
             patch("aiwaf.django.middleware.get_rate_limit_overrides", return_value={}), \
             patch("aiwaf.django.middleware.BlocklistManager.block") as mock_block, \
             patch("aiwaf.django.middleware.time", new=fake_time):
            first = middleware(request)
            second = middleware(request)

        self.assertIsNotNone(first)
        self.assertIsInstance(second, JsonResponse)
        self.assertEqual(second.status_code, 429)
        mock_block.assert_not_called()

    @override_settings(
        AIWAF_RATE_WINDOW=10,
        AIWAF_RATE_MAX=1,
        AIWAF_RATE_FLOOD=100,
        AIWAF_RATE_SOFT_BLOCK_BLOCKLIST=True,
    )
    def test_soft_limit_legacy_blocklists_when_enabled(self):
        """Legacy mode: soft-limit 429 also triggers blocklist call."""
        request = self.create_request("/rl-soft-legacy/", headers={"REMOTE_ADDR": "203.0.113.211"})
        middleware = RateLimitMiddleware(self.mock_get_response)
        ticks = iter([0, 1])
        fake_time = types.SimpleNamespace(time=lambda: next(ticks))

        with patch("aiwaf.django.middleware.is_middleware_disabled", return_value=False), \
             patch("aiwaf.django.middleware.is_exempt", return_value=False), \
             patch("aiwaf.django.middleware.is_ip_exempted", return_value=False), \
             patch("aiwaf.django.middleware.get_rate_limit_overrides", return_value={}), \
             patch("aiwaf.django.middleware.BlocklistManager.block") as mock_block, \
             patch("aiwaf.django.middleware.time", new=fake_time):
            _ = middleware(request)
            second = middleware(request)

        self.assertIsInstance(second, JsonResponse)
        self.assertEqual(second.status_code, 429)
        mock_block.assert_called_once()
        args, _ = mock_block.call_args
        self.assertEqual(args[0], "203.0.113.211")
        self.assertEqual(args[1], "Rate limit exceeded")
    


if __name__ == "__main__":
    import unittest
    unittest.main()
