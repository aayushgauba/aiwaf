#!/usr/bin/env python3
"""
Django Unit Test for Conservative Path Validation

Test the conservative path validation approach
"""

import os
import sys

# Setup Django
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
os.environ.setdefault('DJANGO_SETTINGS_MODULE', 'tests.test_settings')

import django
django.setup()

from tests.base_test import AIWAFTestCase
from aiwaf.trainer import path_exists_in_django


class ConservativePathValidationTestCase(AIWAFTestCase):
    """Test Conservative Path Validation functionality"""
    
    def setUp(self):
        super().setUp()
    
    def test_conservative_path_validation(self):
        """Recognizes real Django routes exactly, including slash variants."""
        self.assertTrue(path_exists_in_django("/test/"))
        self.assertTrue(path_exists_in_django("/test"))
        self.assertTrue(path_exists_in_django("test/"))
        self.assertTrue(path_exists_in_django("/admin/login/"))
    
    def test_unknown_include_prefix_not_treated_as_valid(self):
        """Does not assume arbitrary prefixes from include() patterns exist."""
        self.assertFalse(path_exists_in_django("/school/"))
        self.assertFalse(path_exists_in_django("/school/grades/"))
    


if __name__ == "__main__":
    import unittest
    unittest.main()
