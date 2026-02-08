#!/usr/bin/env python3
"""
Django Unit Test for Import Fix

Test AI-WAF Import Fix
This script tests that AI-WAF can be imported without AppRegistryNotReady errors.
"""

import os
import sys
import importlib

# Setup Django
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
os.environ.setdefault('DJANGO_SETTINGS_MODULE', 'tests.test_settings')

import django
django.setup()

from tests.base_test import AIWAFTestCase


class ImportFixTestCase(AIWAFTestCase):
    """Test Import Fix functionality"""
    
    def setUp(self):
        super().setUp()
    
    def test_aiwaf_import(self):
        """Importing aiwaf modules should not raise AppRegistryNotReady."""
        # Import a representative set of modules that historically can trigger registry timing issues.
        for mod in [
            "aiwaf",
            "aiwaf.middleware",
            "aiwaf.middleware_logger",
            "aiwaf.storage",
            "aiwaf.trainer",
        ]:
            imported = importlib.import_module(mod)
            self.assertIsNotNone(imported)
        
        # Example patterns:
        # request = self.create_request('/test/path/')
        # response = self.process_request_through_middleware(MiddlewareClass, request)
        # self.assertEqual(response.status_code, 200)
    


if __name__ == "__main__":
    import unittest
    unittest.main()
