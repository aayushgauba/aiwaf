#!/usr/bin/env python3
"""
Django Unit Test for Malicious Keywords Fix

Test to verify that the malicious_keywords attribute error is fixed.
"""

import os
import sys
from unittest.mock import patch, MagicMock

# Setup Django
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
os.environ.setdefault('DJANGO_SETTINGS_MODULE', 'tests.test_settings')

import django
django.setup()

from tests.base_test import AIWAFTrainerTestCase
from aiwaf.middleware import IPAndKeywordBlockMiddleware


class MaliciousKeywordsFixTestCase(AIWAFTrainerTestCase):
    """Test Malicious Keywords Fix functionality"""
    
    def setUp(self):
        super().setUp()
    
    def test_middleware_initialization(self):
        """IPAndKeywordBlockMiddleware initializes malicious_keywords set."""
        mw = IPAndKeywordBlockMiddleware(lambda r: None)
        self.assertTrue(hasattr(mw, "malicious_keywords"))
        self.assertIsInstance(mw.malicious_keywords, set)
        
        # Example patterns:
        # request = self.create_request('/test/path/')
        # response = self.process_request_through_middleware(MiddlewareClass, request)
        # self.assertEqual(response.status_code, 200)
    


if __name__ == "__main__":
    import unittest
    unittest.main()
