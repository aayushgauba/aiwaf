#!/usr/bin/env python3
"""Integration tests for extended_request_info via middleware blocks."""

import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
os.environ.setdefault("DJANGO_SETTINGS_MODULE", "tests.test_settings")

import django

django.setup()

from django.core.exceptions import PermissionDenied
from django.test import override_settings
from tests.base_test import AIWAFMiddlewareTestCase
from aiwaf.middleware import HeaderValidationMiddleware
from aiwaf.storage import get_blacklist_store


class ExtendedInfoMiddlewareIntegrationTests(AIWAFMiddlewareTestCase):
    @override_settings(AIWAF_BLACKLIST_STORE_EXTENDED_INFO=True)
    def test_header_validation_block_stores_extended_info(self):
        request = self.create_request(
            "/blocked/",
            headers={
                "REMOTE_ADDR": "203.0.113.88",
            },
        )

        middleware = HeaderValidationMiddleware(self.mock_get_response)
        with self.assertRaises(PermissionDenied):
            middleware.process_request(request)

        entries = get_blacklist_store().get_all()
        entry = next(e for e in entries if e.get("ip_address") == "203.0.113.88")
        info = entry.get("extended_request_info") or {}
        self.assertEqual(info.get("path"), "/blocked/")
        self.assertIn("headers", info)


if __name__ == "__main__":
    import unittest

    unittest.main()
