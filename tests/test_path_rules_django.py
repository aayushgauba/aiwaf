#!/usr/bin/env python3
"""
Django tests for PATH_RULES middleware behavior.
"""

import os
import sys
from unittest.mock import MagicMock

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
os.environ.setdefault("DJANGO_SETTINGS_MODULE", "tests.test_settings")

import django
django.setup()

from django.core.cache import cache
from django.core.exceptions import PermissionDenied
from django.test import override_settings

from tests.base_test import AIWAFTestCase
from aiwaf.middleware import HeaderValidationMiddleware, RateLimitMiddleware


class PathRulesTestCase(AIWAFTestCase):
    def _make_request(self, path, headers=None):
        request = self.create_request(path=path, headers=headers or {})
        request.META["REMOTE_ADDR"] = "10.0.0.1"
        return request

    def test_header_validation_disabled_for_prefix(self):
        settings_block = {
            "PATH_RULES": [
                {
                    "PREFIX": "/api/",
                    "DISABLE": ["HeaderValidationMiddleware"],
                }
            ]
        }
        headers = {"HTTP_USER_AGENT": "", "HTTP_ACCEPT": ""}
        with override_settings(AIWAF_SETTINGS=settings_block, AIWAF_EXEMPT_IPS=[]):
            middleware = HeaderValidationMiddleware(MagicMock())
            response = middleware.process_request(self._make_request("/api/test/", headers=headers))
            self.assertIsNone(response)

            with self.assertRaises(PermissionDenied):
                middleware.process_request(self._make_request("/web/test/", headers=headers))

    def test_rate_limit_uses_most_specific_rule(self):
        settings_block = {
            "PATH_RULES": [
                {"PREFIX": "/api/", "RATE_LIMIT": {"WINDOW": 60, "MAX": 2}},
                {"PREFIX": "/api/v1/", "RATE_LIMIT": {"WINDOW": 60, "MAX": 1}},
            ]
        }
        with override_settings(AIWAF_SETTINGS=settings_block, AIWAF_EXEMPT_IPS=[]):
            cache.clear()
            middleware = RateLimitMiddleware(MagicMock(return_value=MagicMock(status_code=200)))
            request = self._make_request("/api/v1/resource/")

            response = middleware(request)
            self.assertEqual(response.status_code, 200)

            response = middleware(request)
            self.assertEqual(response.status_code, 429)
