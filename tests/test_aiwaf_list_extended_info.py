#!/usr/bin/env python3
"""Tests that aiwaf_list includes extended_request_info in JSON output."""

import os
import sys
import json
from io import StringIO

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
os.environ.setdefault("DJANGO_SETTINGS_MODULE", "tests.test_settings")

import django

django.setup()

from django.core.management import call_command
from tests.base_test import AIWAFStorageTestCase
from aiwaf.storage import get_blacklist_store


class AIWAFListExtendedInfoTests(AIWAFStorageTestCase):
    def test_aiwaf_list_json_includes_extended_info(self):
        store = get_blacklist_store()
        info = {"url": "https://example.com/", "headers": {"User-Agent": "Test"}}
        store.block_ip("203.0.113.57", "Reason", extended_request_info=info)

        out = StringIO()
        call_command("aiwaf_list", "--ips-blocked", "--format", "json", stdout=out)
        payload = json.loads(out.getvalue())

        entries = payload.get("ips_blocked", [])
        entry = next(e for e in entries if e.get("ip_address") == "203.0.113.57")
        self.assertEqual(entry.get("extended_request_info"), info)


if __name__ == "__main__":
    import unittest

    unittest.main()
