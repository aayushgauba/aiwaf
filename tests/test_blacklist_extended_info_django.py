#!/usr/bin/env python3
"""
Tests for blacklist extended request info storage.
"""

import os
import sys
from unittest.mock import MagicMock

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
os.environ.setdefault("DJANGO_SETTINGS_MODULE", "tests.test_settings")

import django

django.setup()

from django.test import override_settings
from tests.base_test import AIWAFStorageTestCase, AIWAFTestCase
from aiwaf.storage import get_blacklist_store
from aiwaf.middleware import _collect_request_headers, _get_blacklist_extended_info


class BlacklistExtendedInfoStorageTests(AIWAFStorageTestCase):
    def test_blacklist_store_persists_extended_info(self):
        store = get_blacklist_store()
        info = {"url": "https://example.com/", "headers": {"User-Agent": "Test"}}
        store.block_ip("203.0.113.55", "Test reason", extended_request_info=info)

        entries = store.get_all()
        self.assertTrue(any(e.get("ip_address") == "203.0.113.55" for e in entries))
        entry = next(e for e in entries if e.get("ip_address") == "203.0.113.55")
        self.assertEqual(entry.get("extended_request_info"), info)


class BlacklistExtendedInfoCaptureTests(AIWAFTestCase):
    @override_settings(AIWAF_BLACKLIST_STORE_EXTENDED_INFO=False)
    def test_extended_info_disabled_returns_none(self):
        request = self.create_request("/test/")
        info = _get_blacklist_extended_info(request)
        self.assertIsNone(info)

    @override_settings(
        AIWAF_BLACKLIST_STORE_EXTENDED_INFO=True,
        AIWAF_BLACKLIST_REDACT_HEADERS=["Authorization"],
        AIWAF_BLACKLIST_MAX_HEADERS=50,
        AIWAF_BLACKLIST_MAX_HEADER_VALUE_LENGTH=5,
    )
    def test_collect_request_headers_redacts_and_truncates(self):
        request = self.create_request(
            "/test/",
            headers={
                "HTTP_AUTHORIZATION": "Bearer secret-token",
                "HTTP_X_LONG": "abcdefghij",
                "HTTP_USER_AGENT": "Mozilla/5.0",
                "HTTP_ACCEPT": "text/html",
            },
        )

        headers = _collect_request_headers(request)
        self.assertEqual(headers.get("Authorization"), "[redacted]")

        long_value = headers.get("X-Long")
        self.assertIsNotNone(long_value)
        self.assertTrue(long_value.endswith("...(truncated)"))

    @override_settings(AIWAF_BLACKLIST_STORE_EXTENDED_INFO=True)
    def test_extended_info_includes_url_and_headers(self):
        request = self.create_request(
            "/magic/",
            headers={
                "HTTP_USER_AGENT": "Mozilla/5.0",
                "HTTP_ACCEPT": "text/html",
            },
        )
        info = _get_blacklist_extended_info(request)
        self.assertIsNotNone(info)
        self.assertEqual(info.get("path"), "/magic/")
        self.assertIn("headers", info)
        self.assertIn("User-Agent", info["headers"])


if __name__ == "__main__":
    import unittest

    unittest.main()
