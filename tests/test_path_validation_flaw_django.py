#!/usr/bin/env python3
"""
Django Unit Test for Path Validation Flaw

Test the path validation flaw scenario
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


class PathValidationFlawTestCase(AIWAFTestCase):
    """Test Path Validation Flaw functionality"""
    
    def setUp(self):
        super().setUp()
    
    def test_path_validation_flaw(self):
        """
        Avoid false positives where a valid prefix is treated as if all subpaths exist.

        In tests.test_urls we have an exact route for /api/users/ but not for /api/users/<id>/.
        `path_exists_in_django` must return False for the subpath so security logic can treat
        it as unknown/non-existent rather than "known safe".
        """
        self.assertTrue(path_exists_in_django("/api/users/"))
        self.assertTrue(path_exists_in_django("/api/users/?page=1"))

        self.assertFalse(path_exists_in_django("/api/users/123/"))
        self.assertFalse(path_exists_in_django("/api/users/123/?page=1"))
    


if __name__ == "__main__":
    import unittest
    unittest.main()
