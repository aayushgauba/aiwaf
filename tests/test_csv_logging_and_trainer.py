#!/usr/bin/env python3
"""
Tests for CSV middleware logging and trainer CSV ingestion.
"""

import os
import sys
import csv
import tempfile
import gzip
from unittest.mock import MagicMock, patch

# Setup Django
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
os.environ.setdefault("DJANGO_SETTINGS_MODULE", "tests.test_settings")

import django
django.setup()

from django.test import override_settings
from django.http import HttpResponse
from django.utils import timezone
from tests.base_test import AIWAFTestCase


class CSVLoggingBehaviorTestCase(AIWAFTestCase):
    def test_csv_header_written_once(self):
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
                middleware.process_response(request, HttpResponse(status=200))
                middleware.process_request(request)
                middleware.process_response(request, HttpResponse(status=200))

            csv_path = log_path.replace(".log", ".csv")
            with open(csv_path, "r", encoding="utf-8") as f:
                lines = f.readlines()
            self.assertEqual(lines[0].strip(), "timestamp,ip,method,path,status_code,content_length,response_time,referer,user_agent")
            self.assertEqual(len(lines), 3)

    def test_csv_disabled_writes_nothing(self):
        from aiwaf.middleware_logger import AIWAFLoggerMiddleware

        with tempfile.TemporaryDirectory() as tmpdir:
            log_path = os.path.join(tmpdir, "aiwaf_requests.log")
            with override_settings(
                AIWAF_MIDDLEWARE_LOGGING=True,
                AIWAF_MIDDLEWARE_LOG=log_path,
                AIWAF_MIDDLEWARE_CSV=False,
                AIWAF_MIDDLEWARE_DB=False,
            ):
                middleware = AIWAFLoggerMiddleware(MagicMock())
                request = self.create_request("/api/ping/")
                middleware.process_request(request)
                middleware.process_response(request, HttpResponse(status=200))

            csv_path = log_path.replace(".log", ".csv")
            self.assertFalse(os.path.exists(csv_path))

    def test_multiple_middleware_appends(self):
        from aiwaf.middleware_logger import AIWAFLoggerMiddleware

        with tempfile.TemporaryDirectory() as tmpdir:
            log_path = os.path.join(tmpdir, "aiwaf_requests.log")
            with override_settings(
                AIWAF_MIDDLEWARE_LOGGING=True,
                AIWAF_MIDDLEWARE_LOG=log_path,
                AIWAF_MIDDLEWARE_CSV=True,
                AIWAF_MIDDLEWARE_DB=False,
            ):
                request = self.create_request("/api/ping/")
                middleware_a = AIWAFLoggerMiddleware(MagicMock())
                middleware_b = AIWAFLoggerMiddleware(MagicMock())
                middleware_a.process_request(request)
                middleware_a.process_response(request, HttpResponse(status=200))
                middleware_b.process_request(request)
                middleware_b.process_response(request, HttpResponse(status=200))

            csv_path = log_path.replace(".log", ".csv")
            with open(csv_path, "r", encoding="utf-8") as f:
                lines = f.readlines()
            self.assertEqual(lines[0].strip(), "timestamp,ip,method,path,status_code,content_length,response_time,referer,user_agent")
            self.assertEqual(len(lines), 3)
    def test_csv_creates_log_directory(self):
        from aiwaf.middleware_logger import AIWAFLoggerMiddleware

        with tempfile.TemporaryDirectory() as tmpdir:
            log_dir = os.path.join(tmpdir, "logs", "aiwaf")
            log_path = os.path.join(log_dir, "aiwaf_requests.log")
            with override_settings(
                AIWAF_MIDDLEWARE_LOGGING=True,
                AIWAF_MIDDLEWARE_LOG=log_path,
                AIWAF_MIDDLEWARE_CSV=True,
                AIWAF_MIDDLEWARE_DB=False,
            ):
                middleware = AIWAFLoggerMiddleware(MagicMock())
                request = self.create_request("/api/ping/")
                middleware.process_request(request)
                middleware.process_response(request, HttpResponse(status=200))

            csv_path = log_path.replace(".log", ".csv")
            self.assertTrue(os.path.isdir(log_dir))
            self.assertTrue(os.path.exists(csv_path))


class TrainerCSVIngestionTestCase(AIWAFTestCase):
    def test_trainer_reads_csv_logs(self):
        from aiwaf.trainer import _read_csv_logs

        with tempfile.TemporaryDirectory() as tmpdir:
            csv_path = os.path.join(tmpdir, "aiwaf_requests.csv")
            with open(csv_path, "w", encoding="utf-8", newline="") as f:
                writer = csv.DictWriter(
                    f,
                    fieldnames=[
                        "timestamp",
                        "ip",
                        "method",
                        "path",
                        "status_code",
                        "content_length",
                        "response_time",
                        "referer",
                        "user_agent",
                    ],
                )
                writer.writeheader()
                writer.writerow(
                    {
                        "timestamp": timezone.now().isoformat(),
                        "ip": "127.0.0.1",
                        "method": "GET",
                        "path": "/api/ping/",
                        "status_code": "200",
                        "content_length": "123",
                        "response_time": "0.123",
                        "referer": "-",
                        "user_agent": "TestAgent/1.0",
                    }
                )

            lines = _read_csv_logs(csv_path)
            self.assertEqual(len(lines), 1)
            self.assertIn("response-time=0.123", lines[0])

    def test_trainer_skips_bad_rows(self):
        from aiwaf.trainer import _read_csv_logs

        with tempfile.TemporaryDirectory() as tmpdir:
            csv_path = os.path.join(tmpdir, "aiwaf_requests.csv")
            with open(csv_path, "w", encoding="utf-8", newline="") as f:
                writer = csv.DictWriter(
                    f,
                    fieldnames=[
                        "timestamp",
                        "ip",
                        "method",
                        "path",
                        "status_code",
                        "content_length",
                        "response_time",
                        "referer",
                        "user_agent",
                    ],
                )
                writer.writeheader()
                writer.writerow(
                    {
                        "timestamp": "not-a-timestamp",
                        "ip": "127.0.0.1",
                        "method": "GET",
                        "path": "/bad/",
                        "status_code": "200",
                        "content_length": "123",
                        "response_time": "0.123",
                        "referer": "-",
                        "user_agent": "TestAgent/1.0",
                    }
                )
                writer.writerow(
                    {
                        "timestamp": timezone.now().isoformat(),
                        "ip": "127.0.0.1",
                        "method": "GET",
                        "path": "/good/",
                        "status_code": "200",
                        "content_length": "123",
                        "response_time": "0.123",
                        "referer": "-",
                        "user_agent": "TestAgent/1.0",
                    }
                )

            lines = _read_csv_logs(csv_path)
            self.assertEqual(len(lines), 1)
            self.assertIn("/good/", lines[0])

    def test_trainer_reads_rotated_csv(self):
        from aiwaf.trainer import _read_all_logs

        with tempfile.TemporaryDirectory() as tmpdir:
            base_path = os.path.join(tmpdir, "aiwaf_requests.csv")
            rotated_path = base_path + ".1"
            for path in (base_path, rotated_path):
                with open(path, "w", encoding="utf-8", newline="") as f:
                    writer = csv.DictWriter(
                        f,
                        fieldnames=[
                            "timestamp",
                            "ip",
                            "method",
                            "path",
                            "status_code",
                            "content_length",
                            "response_time",
                            "referer",
                            "user_agent",
                        ],
                    )
                    writer.writeheader()
                    writer.writerow(
                        {
                            "timestamp": timezone.now().isoformat(),
                            "ip": "127.0.0.1",
                            "method": "GET",
                            "path": "/ok/",
                            "status_code": "200",
                            "content_length": "123",
                            "response_time": "0.123",
                            "referer": "-",
                            "user_agent": "TestAgent/1.0",
                        }
                    )

            with override_settings(AIWAF_ACCESS_LOG=base_path), patch("aiwaf.trainer.LOG_PATH", base_path):
                lines = _read_all_logs()
            ok_count = sum(1 for line in lines if "/ok/" in line)
            self.assertGreaterEqual(ok_count, 2)

    def test_trainer_reads_gzipped_csv(self):
        from aiwaf.trainer import _read_all_logs

        with tempfile.TemporaryDirectory() as tmpdir:
            base_path = os.path.join(tmpdir, "aiwaf_requests.csv")
            gz_path = base_path + ".1.gz"
            with open(base_path, "w", encoding="utf-8") as f:
                f.write("")
            with gzip.open(gz_path, "wt", encoding="utf-8", newline="") as f:
                writer = csv.DictWriter(
                    f,
                    fieldnames=[
                        "timestamp",
                        "ip",
                        "method",
                        "path",
                        "status_code",
                        "content_length",
                        "response_time",
                        "referer",
                        "user_agent",
                    ],
                )
                writer.writeheader()
                writer.writerow(
                    {
                        "timestamp": timezone.now().isoformat(),
                        "ip": "127.0.0.1",
                        "method": "GET",
                        "path": "/gz/",
                        "status_code": "200",
                        "content_length": "123",
                        "response_time": "0.123",
                        "referer": "-",
                        "user_agent": "TestAgent/1.0",
                    }
                )

            with override_settings(AIWAF_ACCESS_LOG=base_path), patch("aiwaf.trainer.LOG_PATH", base_path):
                lines = _read_all_logs()
            self.assertTrue(any("/gz/" in line for line in lines))

    def test_trainer_reads_large_csv(self):
        from aiwaf.trainer import _read_csv_logs

        with tempfile.TemporaryDirectory() as tmpdir:
            csv_path = os.path.join(tmpdir, "aiwaf_requests.csv")
            with open(csv_path, "w", encoding="utf-8", newline="") as f:
                writer = csv.DictWriter(
                    f,
                    fieldnames=[
                        "timestamp",
                        "ip",
                        "method",
                        "path",
                        "status_code",
                        "content_length",
                        "response_time",
                        "referer",
                        "user_agent",
                    ],
                )
                writer.writeheader()
                for i in range(1000):
                    writer.writerow(
                        {
                            "timestamp": timezone.now().isoformat(),
                            "ip": "127.0.0.1",
                            "method": "GET",
                            "path": "/bulk/{}/".format(i),
                            "status_code": "200",
                            "content_length": "123",
                            "response_time": "0.123",
                            "referer": "-",
                            "user_agent": "TestAgent/1.0",
                        }
                    )

            lines = _read_csv_logs(csv_path)
            self.assertEqual(len(lines), 1000)
