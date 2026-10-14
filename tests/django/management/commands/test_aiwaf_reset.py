#!/usr/bin/env python3
"""
Django Unit Test for Aiwaf Reset

Test script for the enhanced aiwaf_reset command

This script simulates the new aiwaf_reset functionality to verify
that it can clear blocklist, exemptions, and keywords separately or together.
"""

import os
import sys
from io import StringIO

# Setup Django
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
os.environ.setdefault('DJANGO_SETTINGS_MODULE', 'tests.test_settings')

import django
django.setup()

from django.core.management import call_command
from tests.django.base_test import AIWAFTestCase
from aiwaf.django.storage import get_blocklist_store, get_exemption_store, get_keyword_store
from aiwaf.django.management.commands.aiwaf_reset import Command


class AiwafResetTestCase(AIWAFTestCase):
    """Test Aiwaf Reset functionality"""
    
    def setUp(self):
        super().setUp()
        self.blocklist_store = get_blocklist_store()
        self.exemption_store = get_exemption_store()
        self.keyword_store = get_keyword_store()
    
    def _seed_stores(self):
        self.blocklist_store.block_ip("203.0.113.1", "testing")
        self.exemption_store.add_exemption("203.0.113.2", "testing")
        self.keyword_store.add_keyword("login")
    
    def test_aiwaf_reset_enhancements(self):
        """Resets all stores when run without explicit flags."""
        self._seed_stores()
        out = StringIO()
        call_command("aiwaf_reset", "--confirm", stdout=out)
        
        self.assertEqual(self.blocklist_store.get_all(), [])
        self.assertEqual(self.exemption_store.get_all(), [])
        self.assertEqual(list(self.keyword_store.get_all_keywords()), [])
    
    def test_command_line_examples(self):
        """Selective flags only clear targeted stores."""
        self._seed_stores()
        out = StringIO()
        call_command("aiwaf_reset", "--blocklist", "--confirm", stdout=out)
        
        self.assertEqual(self.blocklist_store.get_all(), [])
        # Other stores remain untouched
        self.assertNotEqual(self.exemption_store.get_all(), [])
        self.assertNotEqual(list(self.keyword_store.get_all_keywords()), [])
        
        # Legacy flag still works
        self.blocklist_store.block_ip("203.0.113.3", "legacy")
        out = StringIO()
        call_command("aiwaf_reset", "--blocklist-only", "--confirm", stdout=out)
        self.assertEqual(self.blocklist_store.get_all(), [])
    
    def test_help_output(self):
        """Help text lists the new and legacy flags."""
        parser = Command().create_parser("manage.py", "aiwaf_reset")
        help_text = parser.format_help()
        self.assertIn("--blocklist", help_text)
        self.assertIn("--exemptions-only", help_text)
        self.assertIn("--confirm", help_text)
    


if __name__ == "__main__":
    import unittest
    unittest.main()
