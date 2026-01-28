#!/usr/bin/env python3
"""
Integration tests for the Rust backend (real extension module).
Skips if aiwaf_rust isn't available.
"""

import os
import sys
import tempfile

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from django.test import TestCase

try:
    import aiwaf_rust
except Exception:
    aiwaf_rust = None


class RustBackendIntegrationTests(TestCase):
    @classmethod
    def setUpClass(cls):
        super().setUpClass()
        if aiwaf_rust is None:
            raise AssertionError(
                "aiwaf_rust extension not available. Build it with: "
                "maturin develop -m aiwaf_rust/Cargo.toml"
            )

    def test_validate_headers_blocks_missing(self):
        result = aiwaf_rust.validate_headers(
            {"HTTP_USER_AGENT": "Mozilla/5.0"}
        )
        self.assertIsNotNone(result)
        self.assertIn("Missing required headers", result)

    def test_validate_headers_allows_legit(self):
        result = aiwaf_rust.validate_headers(
            {
                "HTTP_USER_AGENT": "Mozilla/5.0 (Windows NT 10.0; Win64; x64)",
                "HTTP_ACCEPT": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
                "HTTP_ACCEPT_LANGUAGE": "en-US,en;q=0.5",
                "HTTP_ACCEPT_ENCODING": "gzip, deflate",
                "HTTP_CONNECTION": "keep-alive",
            }
        )
        self.assertIsNone(result)

    def test_validate_headers_allows_legit_bot(self):
        result = aiwaf_rust.validate_headers(
            {
                "HTTP_USER_AGENT": "Googlebot/2.1 (+http://www.google.com/bot.html)",
                "HTTP_ACCEPT": "*/*",
                "HTTP_ACCEPT_LANGUAGE": "en-US",
            }
        )
        self.assertIsNone(result)

    def test_validate_headers_blocks_accept_star_missing_lang(self):
        result = aiwaf_rust.validate_headers(
            {
                "HTTP_USER_AGENT": "Mozilla/5.0 (Windows NT 10.0; Win64; x64)",
                "HTTP_ACCEPT": "*/*",
            }
        )
        self.assertIsNotNone(result)
        self.assertIn("Generic Accept header", result)

    def test_validate_headers_blocks_http10_chrome(self):
        result = aiwaf_rust.validate_headers(
            {
                "HTTP_USER_AGENT": "Mozilla/5.0 Chrome/120.0.0.0",
                "HTTP_ACCEPT": "text/html",
                "HTTP_ACCEPT_LANGUAGE": "en-US",
                "SERVER_PROTOCOL": "HTTP/1.0",
            }
        )
        self.assertIsNotNone(result)
        self.assertIn("HTTP/1.0", result)

    def test_write_csv_log_writes_header_and_row(self):
        with tempfile.TemporaryDirectory() as tmp:
            csv_path = os.path.join(tmp, "aiwaf_rust_test.csv")
            ok = aiwaf_rust.write_csv_log(
                csv_path,
                ["timestamp", "ip", "method"],
                {"timestamp": "t", "ip": "127.0.0.1", "method": "GET"},
            )
            self.assertTrue(ok)
            with open(csv_path, "r", encoding="utf-8") as f:
                lines = [line.strip() for line in f.readlines() if line.strip()]
            self.assertGreaterEqual(len(lines), 2)
            self.assertIn("timestamp", lines[0])

    def test_write_csv_log_appends_rows(self):
        with tempfile.TemporaryDirectory() as tmp:
            csv_path = os.path.join(tmp, "aiwaf_rust_test.csv")
            ok1 = aiwaf_rust.write_csv_log(
                csv_path,
                ["timestamp", "ip", "method"],
                {"timestamp": "t1", "ip": "127.0.0.1", "method": "GET"},
            )
            ok2 = aiwaf_rust.write_csv_log(
                csv_path,
                ["timestamp", "ip", "method"],
                {"timestamp": "t2", "ip": "127.0.0.2", "method": "POST"},
            )
            self.assertTrue(ok1)
            self.assertTrue(ok2)
            with open(csv_path, "r", encoding="utf-8") as f:
                lines = [line.strip() for line in f.readlines() if line.strip()]
            self.assertEqual(lines[0], "timestamp,ip,method")
            self.assertEqual(lines[1], "t1,127.0.0.1,GET")
            self.assertEqual(lines[2], "t2,127.0.0.2,POST")

    def test_write_csv_log_creates_directory(self):
        with tempfile.TemporaryDirectory() as tmp:
            nested_dir = os.path.join(tmp, "nested", "dir")
            csv_path = os.path.join(nested_dir, "aiwaf_rust_test.csv")
            ok = aiwaf_rust.write_csv_log(
                csv_path,
                ["timestamp", "ip"],
                {"timestamp": "t", "ip": "127.0.0.1"},
            )
            self.assertTrue(ok)
            self.assertTrue(os.path.exists(csv_path))


if __name__ == "__main__":
    import unittest
    unittest.main()
