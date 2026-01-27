#!/usr/bin/env python3
"""
Tests for JsonExceptionMiddleware.
"""

import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
os.environ.setdefault("DJANGO_SETTINGS_MODULE", "tests.test_settings")

import django
django.setup()

from django.core.exceptions import PermissionDenied
from django.http import JsonResponse
from tests.base_test import AIWAFTestCase


class JsonExceptionMiddlewareTestCase(AIWAFTestCase):
    def _json_request(self, path="/"):
        request = self.create_request(path=path)
        request.content_type = "application/json"
        return request

    def test_permission_denied_returns_json(self):
        from aiwaf.middleware import JsonExceptionMiddleware

        request = self._json_request()
        middleware = JsonExceptionMiddleware(lambda req: None)
        response = middleware.process_exception(request, PermissionDenied("blocked"))

        self.assertIsInstance(response, JsonResponse)
        self.assertEqual(response.status_code, 403)
        self.assertEqual(response.content.decode("utf-8"), '{"error": "blocked"}')

    def test_empty_permission_denied_message_uses_default(self):
        from aiwaf.middleware import JsonExceptionMiddleware

        request = self._json_request()
        middleware = JsonExceptionMiddleware(lambda req: None)
        response = middleware.process_exception(request, PermissionDenied())

        self.assertIsInstance(response, JsonResponse)
        self.assertEqual(response.status_code, 403)
        self.assertEqual(response.content.decode("utf-8"), '{"error": "Access denied"}')

    def test_non_json_request_returns_none(self):
        from aiwaf.middleware import JsonExceptionMiddleware

        request = self.create_request(path="/")
        middleware = JsonExceptionMiddleware(lambda req: None)
        response = middleware.process_exception(request, PermissionDenied("blocked"))

        self.assertIsNone(response)

    def test_non_permission_denied_returns_none(self):
        from aiwaf.middleware import JsonExceptionMiddleware

        request = self._json_request()
        middleware = JsonExceptionMiddleware(lambda req: None)
        response = middleware.process_exception(request, RuntimeError("boom"))

        self.assertIsNone(response)


if __name__ == "__main__":
    import unittest
    unittest.main()
