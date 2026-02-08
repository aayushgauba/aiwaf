#!/usr/bin/env python3
"""
Django Unit Test for Method Validation

Test comprehensive HTTP method validation in HoneypotTimingMiddleware

This test verifies that the middleware correctly:
1. Blocks GET requests to POST-only views
2. Blocks POST requests to GET-only views  
3. Blocks other methods (PUT, DELETE) to views that don't support them
4. Allows valid method combinations
"""

import os
import sys
import types
from unittest.mock import MagicMock, patch

# Setup Django
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
os.environ.setdefault('DJANGO_SETTINGS_MODULE', 'tests.test_settings')

import django
django.setup()

from django.test import override_settings
from tests.base_test import AIWAFMiddlewareTestCase
from aiwaf.middleware import HoneypotTimingMiddleware


class MethodValidationTestCase(AIWAFMiddlewareTestCase):
    """Test Method Validation functionality"""
    
    def setUp(self):
        super().setUp()
        from django.core.cache import cache
        cache.clear()

    def _mk_request(self, method, path):
        method = method.upper()
        headers = {"REMOTE_ADDR": "203.0.113.160"}
        if method == "GET":
            return self.factory.get(path, **headers)
        if method == "POST":
            return self.factory.post(path, data={"x": "1"}, **headers)
        if method == "PUT":
            return self.factory.put(path, data="{}", content_type="application/json", **headers)
        if method == "DELETE":
            return self.factory.delete(path, **headers)
        if method == "HEAD":
            return self.factory.head(path, **headers)
        if method == "OPTIONS":
            return self.factory.options(path, **headers)
        return self.factory.generic(method, path, **headers)

    def _run(self, request, accepts=None, blocked=True):
        """
        Run HoneypotTimingMiddleware.process_request with patched dependencies.

        accepts: dict like {"GET": True, "POST": False, "PUT": False}
        blocked: if True, BlacklistManager.is_blocked returns True so the middleware returns 405 JsonResponse.
        """
        middleware = HoneypotTimingMiddleware(self.mock_get_response)
        if accepts is not None:
            middleware._view_accepts_method = MagicMock(
                side_effect=lambda _req, m: accepts.get(m.upper(), True)
            )

        with patch("aiwaf.middleware.is_middleware_disabled", return_value=False), \
             patch("aiwaf.middleware.is_exempt", return_value=False), \
             patch("aiwaf.middleware.is_ip_exempted", return_value=False), \
             patch("aiwaf.middleware.BlacklistManager.block") as mock_block, \
             patch("aiwaf.middleware.BlacklistManager.is_blocked", return_value=blocked):
            response = middleware.process_request(request)
        return response, mock_block
    
    def test_get_to_post_only_view_blocked(self):
        """GET to an obvious POST-only endpoint (e.g. /create/) is blocked when GET unsupported."""
        request = self._mk_request("GET", "/api/create/")
        response, mock_block = self._run(request, accepts={"GET": False})
        self.assertIsNotNone(response)
        self.assertEqual(response.status_code, 405)
        mock_block.assert_called_once()
    
    def test_post_to_get_only_view_blocked(self):
        """POST to GET-only view is blocked when POST unsupported."""
        request = self._mk_request("POST", "/web/test/")
        response, mock_block = self._run(request, accepts={"POST": False})
        self.assertIsNotNone(response)
        self.assertEqual(response.status_code, 405)
        mock_block.assert_called_once()
    
    def test_valid_get_to_get_view_allowed(self):
        """Valid GET is allowed (no block response)."""
        request = self._mk_request("GET", "/web/test/")
        response, mock_block = self._run(request, accepts={"GET": True})
        self.assertIsNone(response)
        mock_block.assert_not_called()
    
    def test_valid_post_to_post_view_allowed(self):
        """Valid POST is allowed when view accepts POST (timing checks may still apply)."""
        request = self._mk_request("POST", "/web/submit/")
        # If no preceding GET exists, timing checks don't run; POST should pass.
        response, mock_block = self._run(request, accepts={"POST": True})
        self.assertIsNone(response)
        mock_block.assert_not_called()
    
    def test_put_to_non_rest_view_blocked(self):
        """Non-GET/POST methods are blocked if the view doesn't support them."""
        request = self._mk_request("PUT", "/web/test/")
        response, mock_block = self._run(request, accepts={"PUT": False})
        self.assertIsNotNone(response)
        self.assertEqual(response.status_code, 405)
        mock_block.assert_called_once()
    
    def test_delete_to_rest_view_allowed(self):
        """DELETE is allowed if the view supports it."""
        request = self._mk_request("DELETE", "/api/v1/resource/")
        response, mock_block = self._run(request, accepts={"DELETE": True})
        self.assertIsNone(response)
        mock_block.assert_not_called()
    
    def test_function_based_view_get_validation(self):
        """If method detection fails, middleware is permissive (does not block)."""
        request = self._mk_request("GET", "/anything/")
        middleware = HoneypotTimingMiddleware(self.mock_get_response)
        with patch("aiwaf.middleware.is_middleware_disabled", return_value=False), \
             patch("aiwaf.middleware.is_exempt", return_value=False), \
             patch("aiwaf.middleware.is_ip_exempted", return_value=False), \
             patch("django.urls.resolve", side_effect=Exception("resolve failed")), \
             patch("aiwaf.middleware.BlacklistManager.block") as mock_block:
            response = middleware.process_request(request)
        self.assertIsNone(response)
        mock_block.assert_not_called()
    
    def test_function_based_view_post_validation(self):
        """POST-only check triggers when middleware is sure POST unsupported."""
        request = self._mk_request("POST", "/anything/")
        response, mock_block = self._run(request, accepts={"POST": False})
        self.assertIsNotNone(response)
        self.assertEqual(response.status_code, 405)
        mock_block.assert_called_once()
    
    def test_head_options_always_allowed(self):
        """HEAD and OPTIONS are always allowed (no method validation)."""
        head = self._mk_request("HEAD", "/web/test/")
        options = self._mk_request("OPTIONS", "/web/test/")
        middleware = HoneypotTimingMiddleware(self.mock_get_response)
        with patch("aiwaf.middleware.is_middleware_disabled", return_value=False), \
             patch("aiwaf.middleware.is_exempt", return_value=False), \
             patch("aiwaf.middleware.is_ip_exempted", return_value=False), \
             patch("aiwaf.middleware.BlacklistManager.block") as mock_block:
            self.assertIsNone(middleware.process_request(head))
            self.assertIsNone(middleware.process_request(options))
        mock_block.assert_not_called()
    
    def test_run_tests(self):
        """Page timeout triggers a 409 and forces a fresh GET by clearing the cache key."""
        from django.core.cache import cache
        ip = "203.0.113.162"
        request = self._mk_request("POST", "/web/post/")
        request.META["REMOTE_ADDR"] = ip
        cache.set(f"honeypot_get:{ip}", 0.0, timeout=300)

        middleware = HoneypotTimingMiddleware(self.mock_get_response)
        middleware._view_accepts_method = MagicMock(return_value=True)

        fake_time = types.SimpleNamespace(time=lambda: 10_000.0)
        with patch("aiwaf.middleware.is_middleware_disabled", return_value=False), \
             patch("aiwaf.middleware.is_exempt", return_value=False), \
             patch("aiwaf.middleware.is_ip_exempted", return_value=False), \
             patch("aiwaf.middleware.time", new=fake_time):
            response = middleware.process_request(request)

        self.assertIsNotNone(response)
        self.assertEqual(response.status_code, 409)
        self.assertIsNone(cache.get(f"honeypot_get:{ip}"))
    


if __name__ == "__main__":
    import unittest
    unittest.main()
