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

from tests.django.base_test import AIWAFTestCase


class BasicImportTestCase(AIWAFTestCase):
    """Ensure every top-level module loads cleanly during startup."""
    
    def test_basic_aiwaf_import(self):
        """Core aiwaf module loads and Django entrypoint is importable."""
        importlib.import_module("aiwaf")
        django_mod = importlib.import_module("aiwaf.django")
        self.assertIsNotNone(django_mod)
    
    def test_middleware_import(self):
        """Middleware module exposes key classes."""
        middleware = importlib.import_module("aiwaf.django.middleware")
        # Sanity check that major middleware classes are present
        self.assertTrue(hasattr(middleware, "HeaderValidationMiddleware"))
        self.assertTrue(hasattr(middleware, "AIAnomalyMiddleware"))
    
    def test_storage_import(self):
        """Storage factory functions are callable and usable."""
        storage = importlib.import_module("aiwaf.django.storage")
        blocklist_store = storage.get_blocklist_store()
        self.assertTrue(hasattr(blocklist_store, "block_ip"))
        self.assertTrue(callable(storage.get_keyword_store))
    
    def test_trainer_import(self):
        """Trainer helpers are available."""
        trainer = importlib.import_module("aiwaf.django.trainer")
        self.assertTrue(callable(trainer.path_exists_in_django))
        self.assertIsInstance(trainer.STATIC_KW, list)
    
    def test_utils_import(self):
        """Utility helpers load without error."""
        utils = importlib.import_module("aiwaf.django.utils")
        self.assertTrue(callable(utils.get_ip))
        self.assertTrue(callable(utils.is_exempt_path))
    
    def test_models_import(self):
        """Models module defines the expected ORM classes."""
        models = importlib.import_module("aiwaf.django.models")
        self.assertTrue(hasattr(models, "BlocklistEntry"))
        self.assertTrue(hasattr(models, "IPExemption"))
        fields = {field.name for field in models.BlocklistEntry._meta.fields}
        self.assertTrue({
            "reputation_reason",
            "reasons",
            "score",
            "offenses",
            "blocked_at",
            "expires_at",
            "duration",
            "permanent",
        }.issubset(fields))
    
    def test_apps_import(self):
        """AppConfig can be imported for Django registration."""
        apps_mod = importlib.import_module("aiwaf.django.apps")
        self.assertTrue(hasattr(apps_mod, "AiwafConfig"))
    


if __name__ == "__main__":
    import unittest
    unittest.main()
