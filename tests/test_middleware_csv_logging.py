#!/usr/bin/env python3
"""
Django Unit Tests for AIWAF CSV middleware logging.
"""

import os
import sys
import csv
import tempfile
from unittest.mock import MagicMock

# Setup Django
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
os.environ.setdefault("DJANGO_SETTINGS_MODULE", "tests.test_settings")

import django
django.setup()

from django.test import override_settings
from django.http import HttpResponse
from tests.base_test import AIWAFTestCase


class CSVLoggingMiddlewareTestCase(AIWAFTestCase):
    def test_csv_log_written(self):
        from aiwaf.middleware_logger import AIWAFLoggerMiddleware

        with tempfile.TemporaryDirectory() as tmpdir:
            log_path = os.path.join(tmpdir, "aiwaf_requests.log")
            with override_settings(
                AIWAF_MIDDLEWARE_LOGGING=True,
                AIWAF_MIDDLEWARE_LOG=log_path,
                AIWAF_MIDDLEWARE_CSV=True,
                AIWAF_MIDDLEWARE_DB=False,
            ):
                middleware = AIWAFLoggerMiddleware(MagicMock())
                request = self.create_request("/api/ping/")
                middleware.process_request(request)
                response = middleware.process_response(request, HttpResponse(status=200))

            csv_path = log_path.replace(".log", ".csv")
            self.assertTrue(os.path.exists(csv_path))
            with open(csv_path, "r", encoding="utf-8", newline="") as f:
                reader = list(csv.DictReader(f))
            self.assertEqual(len(reader), 1)
            self.assertEqual(reader[0]["path"], "/api/ping/")
