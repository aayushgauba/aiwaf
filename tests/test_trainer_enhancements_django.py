#!/usr/bin/env python3
"""
Django Unit Test for Trainer Enhancements

AIWAF Trainer Enhancement Test

This test verifies that the enhanced trainer.py correctly:
1. Excludes legitimate keywords from learning
2. Handles exemption settings properly
3. Uses smarter keyword filtering logic
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
from django.test import override_settings


class TrainerEnhancementsTestCase(AIWAFTrainerTestCase):
    """Test Trainer Enhancements functionality"""
    
    def setUp(self):
        super().setUp()
        from aiwaf import trainer
        self.trainer = trainer
    
    def test_legitimate_keywords_function(self):
        """Legitimate keywords include Django route keywords and defaults."""
        kws = self.trainer.get_legitimate_keywords()
        self.assertIsInstance(kws, set)
        self.assertIn("admin", kws)
        self.assertIn("api", kws)
        self.assertIn("users", kws)
        
        # Example patterns:
        # request = self.create_request('/test/path/')
        # response = self.process_request_through_middleware(MiddlewareClass, request)
        # self.assertEqual(response.status_code, 200)
    
    def test_keyword_learning_logic(self):
        """Trainer malicious-context logic is conservative for valid paths."""
        with patch("aiwaf.trainer.path_exists_in_django", return_value=True):
            self.assertFalse(
                self.trainer._is_malicious_context_trainer("/api/users/", "users", status="404")
            )

        with patch("aiwaf.trainer.path_exists_in_django", return_value=False):
            self.assertTrue(
                self.trainer._is_malicious_context_trainer("/wp-admin/install.php", "wp-admin", status="404")
            )
        
        # Example patterns:
        # request = self.create_request('/test/path/')
        # response = self.process_request_through_middleware(MiddlewareClass, request)
        # self.assertEqual(response.status_code, 200)
    
    def test_exemption_removal(self):
        """remove_exempt_keywords removes tokens derived from exempt paths and settings."""
        store = MagicMock()
        store.remove_keyword = MagicMock()

        with override_settings(
            AIWAF_EXEMPT_PATHS=["/api/users/"],
            AIWAF_EXEMPT_KEYWORDS=["secret"],
            AIWAF_ALLOWED_PATH_KEYWORDS=["allowed"],
        ), patch("aiwaf.trainer.get_keyword_store", return_value=store):
            self.trainer.remove_exempt_keywords()

        # Exempt path tokens (length > 3), explicit exempt keywords, and allowed keywords are removed.
        removed = {c.args[0] for c in store.remove_keyword.call_args_list}
        self.assertIn("users", removed)
        self.assertIn("secret", removed)
        self.assertIn("allowed", removed)
        
        # Example patterns:
        # request = self.create_request('/test/path/')
        # response = self.process_request_through_middleware(MiddlewareClass, request)
        # self.assertEqual(response.status_code, 200)
    


if __name__ == "__main__":
    import unittest
    unittest.main()
