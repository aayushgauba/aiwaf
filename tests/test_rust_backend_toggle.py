#!/usr/bin/env python3
"""
Tests for Rust backend toggling in middleware.
"""

import os
import sys
from unittest.mock import MagicMock, patch

from django.test import override_settings

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
os.environ.setdefault("DJANGO_SETTINGS_MODULE", "tests.test_settings")

import django

django.setup()

from tests.base_test import AIWAFMiddlewareTestCase
from aiwaf.middleware import HeaderValidationMiddleware
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
    def test_logger_uses_rust_when_enabled(self):
        request = self.create_request(
            "/blocked/",
            headers={"REMOTE_ADDR": "10.0.0.1"},
        )
        response = MagicMock(status_code=200)
        response.get.return_value = "-"

        with patch("aiwaf.middleware_logger.rust_available", return_value=True), patch(
            "aiwaf.middleware_logger.rust_write_csv_log", return_value=True
        ) as rust_writer, patch.object(
            AIWAFLoggerMiddleware, "_write_csv_log"
        ) as py_writer:
            middleware = AIWAFLoggerMiddleware(self.mock_get_response)
            middleware.process_request(request)
            middleware.process_response(request, response)

        rust_writer.assert_called_once()
        py_writer.assert_not_called()

    @override_settings(
        AIWAF_USE_RUST=True, AIWAF_MIDDLEWARE_CSV=True, AIWAF_MIDDLEWARE_LOGGING=True
    )
    def test_logger_falls_back_to_python_when_rust_fails(self):
        request = self.create_request(
            "/blocked/",
            headers={"REMOTE_ADDR": "10.0.0.1"},
        )
        response = MagicMock(status_code=200)
        response.get.return_value = "-"

        with patch("aiwaf.middleware_logger.rust_available", return_value=True), patch(
            "aiwaf.middleware_logger.rust_write_csv_log", return_value=False
        ), patch.object(
            AIWAFLoggerMiddleware, "_write_csv_log"
        ) as py_writer:
            middleware = AIWAFLoggerMiddleware(self.mock_get_response)
            middleware.process_request(request)
            middleware.process_response(request, response)

        py_writer.assert_called_once()
