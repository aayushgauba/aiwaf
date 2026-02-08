#!/usr/bin/env python3
"""
Django Unit Test for Unified Keyword Logic

Test that trainer and middleware use unified keyword detection logic
"""

import os
import sys
from unittest.mock import MagicMock, patch

# Setup Django
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
os.environ.setdefault('DJANGO_SETTINGS_MODULE', 'tests.test_settings')

import django
django.setup()

from tests.base_test import AIWAFTrainerTestCase
from aiwaf.middleware import AIAnomalyMiddleware
from aiwaf.trainer import _is_malicious_context_trainer


class UnifiedKeywordLogicTestCase(AIWAFTrainerTestCase):
    """Test Unified Keyword Logic functionality"""
    
    def setUp(self):
        super().setUp()
    
    def test_unified_keyword_logic(self):
        """Trainer and middleware agree on malicious context for obvious attack paths."""
        path = "/wp-admin/install.php"
        self.assertTrue(_is_malicious_context_trainer(path, "wp-admin", status="404"))

        mw = AIAnomalyMiddleware(lambda r: None)
        req = self.create_request(path)
        req.META["REMOTE_ADDR"] = "203.0.113.199"
        with patch("aiwaf.middleware.path_exists_in_django", return_value=False):
            self.assertTrue(mw._is_malicious_context(req, "wp-admin"))
        
        # Example patterns:
        # request = self.create_request('/test/path/')
        # response = self.process_request_through_middleware(MiddlewareClass, request)
        # self.assertEqual(response.status_code, 200)
    
    def test_trainer_logic(self):
        """Trainer does not mark valid Django routes as malicious context."""
        with patch("aiwaf.trainer.path_exists_in_django", return_value=True):
            self.assertFalse(_is_malicious_context_trainer("/api/users/", "users", status="404"))
        
        # Example patterns:
        # request = self.create_request('/test/path/')
        # response = self.process_request_through_middleware(MiddlewareClass, request)
        # self.assertEqual(response.status_code, 200)
    
    def test_middleware_logic(self):
        """Middleware is conservative on valid paths (won't call it malicious)."""
        mw = AIAnomalyMiddleware(lambda r: None)
        req = self.create_request("/api/users/")
        req.META["REMOTE_ADDR"] = "203.0.113.198"
        with patch("aiwaf.middleware.path_exists_in_django", return_value=True):
            self.assertFalse(mw._is_malicious_context(req, "users"))
        
        # Example patterns:
        # request = self.create_request('/test/path/')
        # response = self.process_request_through_middleware(MiddlewareClass, request)
        # self.assertEqual(response.status_code, 200)
    
    def test_consistency(self):
        """Both implementations return booleans and match for a few sample paths."""
        samples = [
            ("/.env", "env", "404", True),
            ("/static/app.js", "static", "200", False),
        ]
        mw = AIAnomalyMiddleware(lambda r: None)
        for path, kw, status, expected in samples:
            req = self.create_request(path)
            req.META["REMOTE_ADDR"] = "203.0.113.197"
            with patch("aiwaf.middleware.path_exists_in_django", return_value=False), \
                 patch("aiwaf.trainer.path_exists_in_django", return_value=False):
                self.assertEqual(_is_malicious_context_trainer(path, kw, status=status), expected)
                self.assertEqual(mw._is_malicious_context(req, kw), expected)
        
        # Example patterns:
        # request = self.create_request('/test/path/')
        # response = self.process_request_through_middleware(MiddlewareClass, request)
        # self.assertEqual(response.status_code, 200)
    


if __name__ == "__main__":
    import unittest
    unittest.main()
