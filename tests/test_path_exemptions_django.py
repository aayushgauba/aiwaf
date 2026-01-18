#!/usr/bin/env python3
"""
Django tests for DB-backed path exemptions and CLI helpers.
"""

import os
import sys
from io import StringIO
from unittest.mock import patch

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
os.environ.setdefault("DJANGO_SETTINGS_MODULE", "tests.test_settings")

import django
django.setup()

from django.core.management import call_command
from django.test import override_settings

from tests.base_test import AIWAFTestCase
from aiwaf.models import ExemptPath
from aiwaf.utils import get_exempt_paths, is_exempt_path


class PathExemptionTestCase(AIWAFTestCase):
    def test_get_exempt_paths_merges_settings_and_db(self):
        ExemptPath.objects.create(path="/db/path/", reason="db")
        with override_settings(AIWAF_EXEMPT_PATHS=["/settings/path/"]):
            paths = get_exempt_paths()
        self.assertIn("/db/path/", paths)
        self.assertIn("/settings/path/", paths)

    def test_is_exempt_path_matches_db_prefix(self):
        ExemptPath.objects.create(path="/api/users/", reason="db")
        self.assertTrue(is_exempt_path("/api/users"))
        self.assertTrue(is_exempt_path("/api/users/123/"))
        self.assertFalse(is_exempt_path("/api/other/"))

    def test_add_pathexemption_command_normalizes(self):
        call_command("add_pathexemption", "api/users", reason="cli")
        self.assertTrue(ExemptPath.objects.filter(path="/api/users/").exists())

    def test_pathshell_adds_exemption(self):
        inputs = [
            "cd api",
            "cd users",
            "exempt .",
            "shell reason",
            "exit",
        ]
        with patch("builtins.input", side_effect=inputs):
            call_command("aiwaf_pathshell", stdout=StringIO())
        self.assertTrue(ExemptPath.objects.filter(path="/api/users/").exists())
