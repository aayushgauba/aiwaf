#!/usr/bin/env python3
"""
Django Unit Test for Basic Import

Django Unit Test for Basic AI-WAF Imports
Tests that AI-WAF modules can be imported safely during Django app loading.
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


class BasicImportTestCase(AIWAFTestCase):
    """Ensure every top-level module loads cleanly during startup."""
    
    def test_basic_aiwaf_import(self):
        """Core aiwaf module exposes expected submodules."""
        mod = importlib.import_module("aiwaf")
        self.assertTrue(hasattr(mod, "middleware"))
        self.assertTrue(hasattr(mod, "storage"))
    
    def test_middleware_import(self):
        """Middleware module exposes key classes."""
        middleware = importlib.import_module("aiwaf.middleware")
        # Sanity check that major middleware classes are present
        self.assertTrue(hasattr(middleware, "HeaderValidationMiddleware"))
        self.assertTrue(hasattr(middleware, "AIAnomalyMiddleware"))
    
    def test_storage_import(self):
        """Storage factory functions are callable and usable."""
        storage = importlib.import_module("aiwaf.storage")
        blacklist_store = storage.get_blacklist_store()
        self.assertTrue(hasattr(blacklist_store, "block_ip"))
        self.assertTrue(callable(storage.get_keyword_store))
    
    def test_trainer_import(self):
        """Trainer helpers are available."""
        trainer = importlib.import_module("aiwaf.trainer")
        self.assertTrue(callable(trainer.path_exists_in_django))
        self.assertIsInstance(trainer.STATIC_KW, list)
    
    def test_utils_import(self):
        """Utility helpers load without error."""
        utils = importlib.import_module("aiwaf.utils")
        self.assertTrue(callable(utils.get_ip))
        self.assertTrue(callable(utils.is_exempt_path))
    
    def test_models_import(self):
        """Models module defines the expected ORM classes."""
        models = importlib.import_module("aiwaf.models")
        self.assertTrue(hasattr(models, "BlacklistEntry"))
        self.assertTrue(hasattr(models, "IPExemption"))
    
    def test_apps_import(self):
        """AppConfig can be imported for Django registration."""
        apps_mod = importlib.import_module("aiwaf.apps")
        self.assertTrue(hasattr(apps_mod, "AiwafConfig"))
    


if __name__ == "__main__":
    import unittest
    unittest.main()
