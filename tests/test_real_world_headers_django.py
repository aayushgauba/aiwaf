#!/usr/bin/env python3
"""
Django Unit Test for Real World Headers

Real-World Log Analysis: Header Validation in Action

This demonstrates how the HeaderValidationMiddleware would handle actual log entries:
1. Suspicious request with missing User-Agent
2. Legitimate browser request with full headers
"""

import os
import sys
from unittest.mock import MagicMock, patch

# Setup Django
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
os.environ.setdefault('DJANGO_SETTINGS_MODULE', 'tests.test_settings')

import django
django.setup()

from tests.base_test import AIWAFMiddlewareTestCase
from django.test import override_settings
from aiwaf.middleware import HeaderValidationMiddleware


class RealWorldHeadersTestCase(AIWAFMiddlewareTestCase):
    """Test Real World Headers functionality"""
    
    def setUp(self):
        super().setUp()
    
    def _run_and_capture_reason(self, request):
        with patch.object(
            HeaderValidationMiddleware,
            "_block_request",
            return_value=MagicMock(status_code=403)
        ) as block:
            middleware = HeaderValidationMiddleware(self.mock_get_response)
            response = middleware.process_request(request)
        self.assertIsNotNone(response)
        self.assertEqual(response.status_code, 403)
        return block.call_args[0][2]
    
    def test_basic_functionality(self):
        """Suspicious missing UA blocks; typical browser headers pass."""
        with override_settings(
            AIWAF_USE_RUST=False,
            AIWAF_REQUIRED_HEADERS=["HTTP_USER_AGENT", "HTTP_ACCEPT"],
        ):
            # Suspicious: missing UA
            bad = self.factory.get(
                "/web/",
                HTTP_ACCEPT="text/html",
                REMOTE_ADDR="203.0.113.190",
            )
            reason = self._run_and_capture_reason(bad)
            self.assertIn("Missing required headers", reason)

            # Legit browser-like headers
            good = self.factory.get(
                "/web/",
                HTTP_USER_AGENT="Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36",
                HTTP_ACCEPT="text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
                HTTP_ACCEPT_LANGUAGE="en-US,en;q=0.9",
                HTTP_ACCEPT_ENCODING="gzip, deflate",
                HTTP_CONNECTION="keep-alive",
                REMOTE_ADDR="203.0.113.191",
            )
            middleware = HeaderValidationMiddleware(self.mock_get_response)
            response = middleware.process_request(good)
            self.assertIsNone(response)
    


if __name__ == "__main__":
    import unittest
    unittest.main()
