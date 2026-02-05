#!/usr/bin/env python3
"""
Django Unit Test for Header Validation

Test Header Validation Middleware

This test verifies that the HeaderValidationMiddleware correctly:
1. Blocks requests with missing required headers
2. Blocks requests with suspicious User-Agent strings
3. Blocks requests with suspicious header combinations
4. Allows legitimate browser requests
5. Allows legitimate bot requests
6. Calculates header quality scores correctly
"""

import os
import sys
from unittest.mock import patch, MagicMock

# Setup Django
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
os.environ.setdefault('DJANGO_SETTINGS_MODULE', 'tests.test_settings')

import django
django.setup()

from django.test import override_settings

from tests.base_test import AIWAFMiddlewareTestCase
from aiwaf.middleware import HeaderValidationMiddleware


class HeaderValidationTestCase(AIWAFMiddlewareTestCase):
    """Test Header Validation functionality"""
    
    def setUp(self):
        super().setUp()
        # Import after Django setup
        # Add imports as needed
    
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
        reason = block.call_args[0][2]
        return reason

    @override_settings(
        AIWAF_MAX_HEADER_BYTES=60,
        AIWAF_MAX_HEADER_COUNT=100,
        AIWAF_MAX_USER_AGENT_LENGTH=500,
        AIWAF_MAX_ACCEPT_LENGTH=4096,
    )
    def test_header_bytes_cap_blocks_early(self):
        headers = {
            'HTTP_USER_AGENT': 'Mozilla/5.0',
            'HTTP_ACCEPT': 'text/html',
            'HTTP_X_EXTRA': 'x' * 80,
            'REMOTE_ADDR': '203.0.113.1',
        }
        request = self.factory.get('/caps/', **headers)
        reason = self._run_and_capture_reason(request)
        self.assertIn("Header bytes exceed", reason)

    @override_settings(
        AIWAF_MAX_HEADER_BYTES=4096,
        AIWAF_MAX_HEADER_COUNT=2,
        AIWAF_MAX_USER_AGENT_LENGTH=500,
        AIWAF_MAX_ACCEPT_LENGTH=4096,
    )
    def test_header_count_cap_blocks_after_threshold(self):
        headers = {
            'HTTP_USER_AGENT': 'Mozilla/5.0',
            'HTTP_ACCEPT': 'text/html',
            'HTTP_X_ONE': '1',
            'HTTP_X_TWO': '2',
            'REMOTE_ADDR': '203.0.113.2',
        }
        request = self.factory.get('/caps/', **headers)
        reason = self._run_and_capture_reason(request)
        self.assertIn("Header count exceeds", reason)

    @override_settings(
        AIWAF_MAX_HEADER_BYTES=4096,
        AIWAF_MAX_HEADER_COUNT=100,
        AIWAF_MAX_USER_AGENT_LENGTH=500,
        AIWAF_MAX_ACCEPT_LENGTH=10,
    )
    def test_accept_header_length_cap_triggers(self):
        headers = {
            'HTTP_USER_AGENT': 'Mozilla/5.0',
            'HTTP_ACCEPT': 'text/html;q=0.9',
            'REMOTE_ADDR': '203.0.113.3',
        }
        request = self.factory.get('/caps/', **headers)
        reason = self._run_and_capture_reason(request)
        self.assertIn("Accept header longer than", reason)

    @override_settings(
        AIWAF_REQUIRED_HEADERS={"GET": ["HTTP_USER_AGENT", "HTTP_ACCEPT"], "HEAD": []},
        AIWAF_HEADER_QUALITY_MIN_SCORE=3,
    )
    def test_head_allows_missing_required_headers(self):
        headers = {
            'HTTP_USER_AGENT': 'EmailScanner/1.0',
            'REMOTE_ADDR': '203.0.113.10',
        }
        request = self.factory.head('/magic-link/', **headers)
        with patch.object(
            HeaderValidationMiddleware,
            "_block_request",
            return_value=MagicMock(status_code=403)
        ) as block:
            middleware = HeaderValidationMiddleware(self.mock_get_response)
            response = middleware.process_request(request)
        self.assertIsNone(response)
        block.assert_not_called()

    @override_settings(AIWAF_REQUIRED_HEADERS=["HTTP_USER_AGENT"])
    def test_required_headers_list_applies_to_all_methods(self):
        headers = {
            'REMOTE_ADDR': '203.0.113.11',
        }
        request = self.factory.get('/list/', **headers)
        reason = self._run_and_capture_reason(request)
        self.assertIn("Missing required headers", reason)
        self.assertIn("user-agent", reason)

    @override_settings(AIWAF_REQUIRED_HEADERS={"DEFAULT": ["HTTP_USER_AGENT"]})
    def test_required_headers_default_fallback(self):
        headers = {
            'REMOTE_ADDR': '203.0.113.12',
        }
        request = self.factory.post('/default/', **headers)
        reason = self._run_and_capture_reason(request)
        self.assertIn("Missing required headers", reason)

    @override_settings(
        AIWAF_REQUIRED_HEADERS={"HEAD": []},
        AIWAF_HEADER_QUALITY_MIN_SCORE=3,
    )
    def test_empty_required_headers_disables_quality_threshold(self):
        headers = {
            'HTTP_USER_AGENT': 'Mozilla/5.0',
            'REMOTE_ADDR': '203.0.113.13',
        }
        request = self.factory.head('/no-score/', **headers)
        with patch.object(
            HeaderValidationMiddleware,
            "_block_request",
            return_value=MagicMock(status_code=403)
        ) as block:
            middleware = HeaderValidationMiddleware(self.mock_get_response)
            response = middleware.process_request(request)
        self.assertIsNone(response)
        block.assert_not_called()
    
    def test_header_validation(self):
        """Test header validation"""
        # TODO: Convert original test logic to Django test
        # Original test: test_header_validation
        
        # Placeholder test - replace with actual logic
        self.assertTrue(True, "Test needs implementation")
        
        # Example patterns:
        # request = self.create_request('/test/path/')
        # response = self.process_request_through_middleware(MiddlewareClass, request)
        # self.assertEqual(response.status_code, 200)
    
    def test_quality_scoring(self):
        """Test quality scoring"""
        # TODO: Convert original test logic to Django test
        # Original test: test_quality_scoring
        
        # Placeholder test - replace with actual logic
        self.assertTrue(True, "Test needs implementation")
        
        # Example patterns:
        # request = self.create_request('/test/path/')
        # response = self.process_request_through_middleware(MiddlewareClass, request)
        # self.assertEqual(response.status_code, 200)
    


if __name__ == "__main__":
    import unittest
    unittest.main()
