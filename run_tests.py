#!/usr/bin/env python3
"""
Django Test Runner for AIWAF
This script allows running AIWAF tests using Django's test framework.
"""

import os
import sys
import django
from django.conf import settings
from django.test.utils import get_runner


def run_tests():
    """Run AIWAF Django unit tests"""
    
    # Add the project root to Python path
    project_root = os.path.dirname(os.path.abspath(__file__))
    sys.path.insert(0, project_root)
    
    # Configure Django settings
    os.environ.setdefault('DJANGO_SETTINGS_MODULE', 'tests.test_settings')
    django.setup()
    
    # Get the test runner
    TestRunner = get_runner(settings)
    test_runner = TestRunner()
    
    # Run tests in the tests directory
    failures = test_runner.run_tests(["tests"])
    
    if failures:
        print(f"\n❌ {failures} test(s) failed!")
        sys.exit(1)
    else:
        print("\n✅ All tests passed!")
        sys.exit(0)


if __name__ == "__main__":
    run_tests()