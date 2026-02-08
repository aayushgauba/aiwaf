#!/usr/bin/env python3
"""
Django Unit Test for Storage Simple

Simple test script to verify the keyword storage fix works.
This test doesn't require any external dependencies.
"""

import os
import sys
from unittest.mock import patch

# Setup Django
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
os.environ.setdefault('DJANGO_SETTINGS_MODULE', 'tests.test_settings')

import django
django.setup()

from tests.base_test import AIWAFStorageTestCase
from aiwaf.storage import get_keyword_store


class StorageSimpleTestCase(AIWAFStorageTestCase):
    """Test Storage Simple functionality"""
    
    def setUp(self):
        super().setUp()
    
    def test_basic_functionality(self):
        """Keyword store persists counts and returns sorted top keywords."""
        store = get_keyword_store()
        # Start clean
        for kw in store.get_all_keywords():
            store.remove_keyword(kw)

        store.add_keyword("alpha", 1)
        store.add_keyword("beta", 3)
        store.add_keyword("alpha", 2)  # alpha total should be 3

        top = store.get_top_keywords(2)
        self.assertEqual(top[0], "alpha")
        self.assertIn("beta", top)
        
        # Example patterns:
        # request = self.create_request('/test/path/')
        # response = self.process_request_through_middleware(MiddlewareClass, request)
        # self.assertEqual(response.status_code, 200)
    


if __name__ == "__main__":
    import unittest
    unittest.main()
