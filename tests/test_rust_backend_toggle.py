#!/usr/bin/env python3
"""
Tests for Rust backend toggling in middleware.
"""

import os
import sys
import time
from unittest.mock import MagicMock, patch

from django.test import override_settings
from django.core.cache import cache

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
os.environ.setdefault("DJANGO_SETTINGS_MODULE", "tests.test_settings")

import django

django.setup()

from tests.base_test import AIWAFMiddlewareTestCase
from aiwaf.middleware import HeaderValidationMiddleware, AIAnomalyMiddleware
from aiwaf.middleware_logger import AIWAFLoggerMiddleware
from aiwaf.utils import get_ip
from aiwaf.middleware_logger import AIWAFLoggerMiddleware


class RustBackendToggleTests(AIWAFMiddlewareTestCase):
    @override_settings(AIWAF_USE_RUST=True, AIWAF_MIDDLEWARE_CSV=True)
    def test_header_validation_uses_rust_when_enabled(self):
        request = self.create_request(
            "/blocked/",
            headers={"REMOTE_ADDR": "10.0.0.1"},
        )

        with patch("aiwaf.middleware.rust_available", return_value=True), patch(
            "aiwaf.middleware.rust_validate_headers", return_value="Rust says no"
        ), patch.object(
            HeaderValidationMiddleware, "_block_request", return_value=MagicMock(status_code=403)
        ) as block:
            middleware = HeaderValidationMiddleware(self.mock_get_response)
            response = middleware.process_request(request)

        self.assertIsNotNone(response)
        self.assertEqual(response.status_code, 403)
        block.assert_called_once()

    @override_settings(
        AIWAF_USE_RUST=True, AIWAF_MIDDLEWARE_CSV=True, AIWAF_MIDDLEWARE_LOGGING=True
    )
    def test_logger_uses_python_csv_logging(self):
        request = self.create_request(
            "/blocked/",
            headers={"REMOTE_ADDR": "10.0.0.1"},
        )
        response = MagicMock(status_code=200)
        response.get.return_value = "-"

        with patch.object(
            AIWAFLoggerMiddleware, "_write_csv_log"
        ) as py_writer:
            middleware = AIWAFLoggerMiddleware(self.mock_get_response)
            middleware.process_request(request)
            middleware.process_response(request, response)

        py_writer.assert_called_once()

    @override_settings(
        AIWAF_USE_RUST=True, AIWAF_MIDDLEWARE_CSV=True, AIWAF_MIDDLEWARE_LOGGING=True
    )
    def test_logger_uses_python_csv_logging_even_if_rust_enabled(self):
        request = self.create_request(
            "/blocked/",
            headers={"REMOTE_ADDR": "10.0.0.1"},
        )
        response = MagicMock(status_code=200)
        response.get.return_value = "-"

        with patch.object(
            AIWAFLoggerMiddleware, "_write_csv_log"
        ) as py_writer:
            middleware = AIWAFLoggerMiddleware(self.mock_get_response)
            middleware.process_request(request)
            middleware.process_response(request, response)

        py_writer.assert_called_once()

    @override_settings(AIWAF_USE_RUST=True)
    def test_ai_anomaly_prefers_rust_behavior_analysis(self):
        middleware = AIAnomalyMiddleware(self.mock_get_response)
        recent_data = [(time.time() - 5, "/wp-admin/", 404, 0.2)]
        stats = {"should_block": False}

        with patch("aiwaf.middleware.rust_available", return_value=True), \
             patch("aiwaf.middleware.path_exists_in_django", return_value=False), \
             patch("aiwaf.middleware.is_exempt_path", return_value=False), \
             patch("aiwaf.middleware.rust_analyze_recent_behavior", return_value=stats) as rust_fn, \
             patch.object(AIAnomalyMiddleware, "_analyze_recent_behavior_python") as py_analyze:
            result = middleware._analyze_recent_behavior(recent_data)

        rust_fn.assert_called_once()
        py_analyze.assert_not_called()
        self.assertEqual(result, stats)

    @override_settings(AIWAF_USE_RUST=True)
    def test_ai_anomaly_falls_back_when_rust_missing(self):
        middleware = AIAnomalyMiddleware(self.mock_get_response)
        recent_data = [(time.time() - 2, "/scan/", 404, 0.1)]
        stats = {"should_block": False}

        with patch("aiwaf.middleware.rust_available", return_value=False), \
             patch("aiwaf.middleware.path_exists_in_django", return_value=False), \
             patch("aiwaf.middleware.is_exempt_path", return_value=False), \
             patch("aiwaf.middleware.rust_analyze_recent_behavior", return_value=None) as rust_fn, \
             patch.object(AIAnomalyMiddleware, "_analyze_recent_behavior_python", return_value=stats) as py_analyze:
            result = middleware._analyze_recent_behavior(recent_data)

        rust_fn.assert_not_called()
        py_analyze.assert_called_once()
        self.assertEqual(result, stats)
