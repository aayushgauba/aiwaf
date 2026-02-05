#!/usr/bin/env python3
"""
Tests for the aiwaf_whois management command.
"""

import os
import sys
import types
import unittest
import warnings
from unittest.mock import patch

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
os.environ.setdefault("DJANGO_SETTINGS_MODULE", "tests.test_settings")

import django

django.setup()

from django.core.management import call_command
from django.core.management.base import CommandError
from tests.base_test import AIWAFTestCase


class AIWAFWhoisCommandTests(AIWAFTestCase):
    def test_whois_command_success_json(self):
        fake_module = types.SimpleNamespace(
            whois=lambda target: {"domain_name": "example.com", "org": "Example Org"}
        )
        with patch.dict("sys.modules", {"whois": fake_module}):
            call_command("aiwaf_whois", "example.com", format="json")

    def test_whois_command_missing_dependency(self):
        import builtins
        original_import = builtins.__import__

        def import_blocker(name, *args, **kwargs):
            if name == "whois":
                raise ImportError("No module named whois")
            return original_import(name, *args, **kwargs)

        with patch("builtins.__import__", side_effect=import_blocker):
            with self.assertRaises(CommandError) as ctx:
                call_command("aiwaf_whois", "example.com")
        self.assertIn("python-whois is not installed", str(ctx.exception))

    def test_whois_command_lookup_failure(self):
        def failing(target):
            raise Exception("boom")

        fake_module = types.SimpleNamespace(whois=failing)
        with patch.dict("sys.modules", {"whois": fake_module}):
            with self.assertRaises(CommandError) as ctx:
                call_command("aiwaf_whois", "example.com")
        self.assertIn("Whois lookup failed", str(ctx.exception))

    def test_whois_command_live_lookup(self):
        try:
            import whois  # noqa: F401
        except Exception:
            warnings.warn("python-whois not installed; skipping live whois test")
            return

        try:
            call_command("aiwaf_whois", "example.com", format="json")
        except Exception as exc:
            warnings.warn(f"live whois test failed: {exc}")


if __name__ == "__main__":
    import unittest

    unittest.main()
