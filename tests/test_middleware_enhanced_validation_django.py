#!/usr/bin/env python3
"""
Django Unit Test for Middleware Enhanced Validation

Test that middleware benefits from the improved path validation
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
from django.test import override_settings
from aiwaf.middleware import IPAndKeywordBlockMiddleware


class MiddlewareEnhancedValidationTestCase(AIWAFMiddlewareTestCase):
    """Test Middleware Enhanced Validation functionality"""
    
    def setUp(self):
        super().setUp()
    
    def test_middleware_with_improved_path_validation(self):
        """Valid paths avoid blocking on static keywords without strong indicators."""
        middleware = IPAndKeywordBlockMiddleware(self.mock_get_response)
        middleware.safe_prefixes = set()

        request = self.factory.get("/api/users/")
        request.META["REMOTE_ADDR"] = "203.0.113.142"

        with override_settings(AIWAF_ENABLE_KEYWORD_LEARNING=True), \
             patch("aiwaf.middleware.is_middleware_disabled", return_value=False), \
             patch("aiwaf.middleware.is_exempt", return_value=False), \
             patch("aiwaf.middleware.is_ip_exempted", return_value=False), \
             patch("aiwaf.middleware.BlacklistManager.is_blocked", return_value=False), \
             patch("aiwaf.middleware.path_exists_in_django", return_value=True), \
             patch("aiwaf.middleware.BlacklistManager.block") as mock_block:
            response = middleware(request)

        self.assertIsNotNone(response)
        mock_block.assert_not_called()
        
        # Example patterns:
        # request = self.create_request('/test/path/')
        # response = self.process_request_through_middleware(MiddlewareClass, request)
        # self.assertEqual(response.status_code, 200)
    


if __name__ == "__main__":
    import unittest
    unittest.main()
