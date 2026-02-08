#!/usr/bin/env python3
"""
Django Unit Test for Rate Limiting Pure Logic

Simple test to verify rate limiting logic step by step.
Tests the core algorithm without Django dependencies.
"""

import os
import sys
import types
from unittest.mock import patch

# Setup Django
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
os.environ.setdefault('DJANGO_SETTINGS_MODULE', 'tests.test_settings')

import django
django.setup()

from django.test import override_settings
from tests.base_test import AIWAFMiddlewareTestCase
from aiwaf.middleware import RateLimitMiddleware


class RateLimitingPureLogicTestCase(AIWAFMiddlewareTestCase):
    """Test Rate Limiting Pure Logic functionality"""
    
    def setUp(self):
        super().setUp()
        from django.core.cache import cache
        cache.clear()
    
    @override_settings(AIWAF_RATE_WINDOW=10, AIWAF_RATE_MAX=100, AIWAF_RATE_FLOOD=100)
    def test_rate_limiting_logic(self):
        """Old timestamps are trimmed to the configured window."""
        from django.core.cache import cache

        ip = "203.0.113.251"
        request = self.create_request("/rl-logic/", headers={"REMOTE_ADDR": ip})
        middleware = RateLimitMiddleware(self.mock_get_response)
        ticks = iter([0, 1, 2, 15])
        fake_time = types.SimpleNamespace(time=lambda: next(ticks))

        with patch("aiwaf.middleware.is_middleware_disabled", return_value=False), \
             patch("aiwaf.middleware.is_exempt", return_value=False), \
             patch("aiwaf.middleware.is_ip_exempted", return_value=False), \
             patch("aiwaf.middleware.get_rate_limit_overrides", return_value={}), \
             patch("aiwaf.middleware.time", new=fake_time):
            middleware(request)
            middleware(request)
            middleware(request)
            # At t=15, older than window=10 should be dropped.
            middleware(request)

        timestamps = cache.get(f"ratelimit:{ip}")
        self.assertEqual(len(timestamps), 1)
    


if __name__ == "__main__":
    import unittest
    unittest.main()
