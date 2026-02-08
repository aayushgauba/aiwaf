#!/usr/bin/env python3
"""
Django Unit Test for Exemption Simple

Simple Exemption Test
Run this to test AI-WAF exemption functionality
Usage: python test_exemption_simple.py
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
from aiwaf.middleware import RateLimitMiddleware
from aiwaf.storage import get_exemption_store
from aiwaf.utils import is_ip_exempted


class ExemptionSimpleTestCase(AIWAFMiddlewareTestCase):
    """Test Exemption Simple functionality"""
    
    def setUp(self):
        super().setUp()
    
    def test_exemption_functionality(self):
        """Settings + DB exemptions are honored and middleware bypasses enforcement."""
        store = get_exemption_store()

        with override_settings(AIWAF_EXEMPT_IPS=["203.0.113.0/24"]):
            self.assertTrue(is_ip_exempted("203.0.113.5"))
            self.assertFalse(is_ip_exempted("198.51.100.5"))

        # DB-backed exemption
        with override_settings(AIWAF_EXEMPT_IPS=[]):
            store.add_exemption("203.0.113.9", reason="test")
            self.assertTrue(is_ip_exempted("203.0.113.9"))

        # Middleware should skip rate limiting entirely for exempted IPs
        with override_settings(AIWAF_EXEMPT_IPS=["203.0.113.10"], AIWAF_RATE_FLOOD=0):
            middleware = RateLimitMiddleware(self.mock_get_response)
            request = self.create_request("/rl/", headers={"REMOTE_ADDR": "203.0.113.10"})
            with patch("aiwaf.middleware.is_middleware_disabled", return_value=False), \
                 patch("aiwaf.middleware.is_exempt", return_value=False), \
                 patch("aiwaf.middleware.BlacklistManager.block") as mock_block:
                response = middleware(request)
            self.assertIsNotNone(response)
            mock_block.assert_not_called()
    


if __name__ == "__main__":
    import unittest
    unittest.main()
