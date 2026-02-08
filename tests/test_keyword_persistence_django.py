#!/usr/bin/env python3
"""
Django Unit Test for Keyword Persistence

Test to verify that learned keywords actually persist to the database.
This test diagnoses the keyword storage persistence issue.
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
from aiwaf.storage import get_keyword_store
from aiwaf.models import DynamicKeyword


class KeywordPersistenceTestCase(AIWAFTrainerTestCase):
    """Test Keyword Persistence functionality"""
    
    def setUp(self):
        super().setUp()
        # Ensure clean keyword table
        DynamicKeyword.objects.all().delete()
    
    def test_keyword_storage_diagnosis(self):
        """Learned keywords persist in DB and survive store re-instantiation."""
        store = get_keyword_store()
        store.add_keyword("persistme", 2)

        self.assertTrue(DynamicKeyword.objects.filter(keyword="persistme").exists())
        self.assertIn("persistme", list(store.get_all_keywords()))

        # New store instance should still see it (DB-backed).
        store2 = get_keyword_store()
        self.assertIn("persistme", list(store2.get_all_keywords()))
        
        # Example patterns:
        # request = self.create_request('/test/path/')
        # response = self.process_request_through_middleware(MiddlewareClass, request)
        # self.assertEqual(response.status_code, 200)
    


if __name__ == "__main__":
    import unittest
    unittest.main()
