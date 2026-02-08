#!/usr/bin/env python3
"""
Django Unit Test for Honeypot Enhancements

Test script for enhanced HoneypotTimingMiddleware features:
1. Checking if view accepts POST requests
2. Page timeout after 4 minutes requiring reload
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


class HoneypotEnhancementsTestCase(AIWAFMiddlewareTestCase):
    """Test Honeypot Enhancements functionality"""
    
    def setUp(self):
        super().setUp()
        cache.clear()

    def _mk_request(self, method, path, ip="203.0.113.170"):
        headers = {"REMOTE_ADDR": ip}
        method = method.upper()
        if method == "GET":
            return self.factory.get(path, **headers)
        if method == "POST":
            return self.factory.post(path, data={"x": "1"}, **headers)
        return self.factory.generic(method, path, **headers)
    
    def test_post_validation_logic(self):
        """Blocks POST to a GET-only view when the middleware can determine POST is unsupported."""
        request = self._mk_request("POST", "/web/test/")
        middleware = HoneypotTimingMiddleware(self.mock_get_response)
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
    
    def test_page_timeout_logic(self):
        """POST after MAX_PAGE_TIME returns 409 and clears the cached GET timestamp."""
        ip = "203.0.113.171"
        cache.set(f"honeypot_get:{ip}", 0.0, timeout=300)
        request = self._mk_request("POST", "/web/post/", ip=ip)
        middleware = HoneypotTimingMiddleware(self.mock_get_response)
        middleware._view_accepts_method = MagicMock(return_value=True)

        fake_time = types.SimpleNamespace(time=lambda: 10_000.0)
        with patch("aiwaf.middleware.is_middleware_disabled", return_value=False), \
             patch("aiwaf.middleware.is_exempt", return_value=False), \
             patch("aiwaf.middleware.is_ip_exempted", return_value=False), \
             patch("aiwaf.middleware.time", new=fake_time):
            response = middleware.process_request(request)

        self.assertIsNotNone(response)
        self.assertEqual(response.status_code, 409)
        self.assertIsNone(cache.get(f"honeypot_get:{ip}"))
    
    def test_middleware_configuration(self):
        """Uses MIN_FORM_TIME to block fast POSTs after a GET."""
        ip = "203.0.113.172"
        get_req = self._mk_request("GET", "/web/form/", ip=ip)
        post_req = self._mk_request("POST", "/web/form/", ip=ip)

        middleware = HoneypotTimingMiddleware(self.mock_get_response)
        middleware._view_accepts_method = MagicMock(return_value=True)

        # GET at t=1000, POST at t=1000.1 (diff=0.1 < MIN_FORM_TIME=1.0).
        ticks = iter([1000.0, 1000.1, 1000.1])
        fake_time = types.SimpleNamespace(time=lambda: next(ticks))

        with patch("aiwaf.middleware.is_middleware_disabled", return_value=False), \
             patch("aiwaf.middleware.is_exempt", return_value=False), \
             patch("aiwaf.middleware.is_ip_exempted", return_value=False), \
             patch("aiwaf.middleware.time", new=fake_time), \
             patch("aiwaf.middleware.BlacklistManager.block") as mock_block, \
             patch("aiwaf.middleware.BlacklistManager.is_blocked", return_value=True), \
             patch("aiwaf.middleware._raise_blocked") as mock_raise:
            self.assertIsNone(middleware.process_request(get_req))
            middleware.process_request(post_req)

        mock_block.assert_called_once()
        mock_raise.assert_called_once()
    


if __name__ == "__main__":
    import unittest
    unittest.main()
