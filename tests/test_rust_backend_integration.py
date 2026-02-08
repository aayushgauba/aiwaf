#!/usr/bin/env python3
"""
Integration tests for the Rust backend (real extension module).
Skips if aiwaf_rust isn't available.
"""

import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from django.test import TestCase
import unittest

try:
    import aiwaf_rust
except Exception:
    aiwaf_rust = None


class RustBackendIntegrationTests(TestCase):
    @classmethod
    def setUpClass(cls):
        super().setUpClass()
        if aiwaf_rust is None:
            raise unittest.SkipTest(
                "aiwaf_rust extension not available (skip Rust integration tests). "
                "Build it with: maturin develop -m Cargo.toml"
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

    def test_analyze_recent_behavior_basic_metrics(self):
        entries = [
            {"path_lower": "/wp-admin/install.php", "timestamp": 0.0, "status": 404, "kw_check": True},
            {"path_lower": "/home", "timestamp": 5.0, "status": 200, "kw_check": False},
        ]
        result = aiwaf_rust.analyze_recent_behavior(entries, [".php", "wp-"])
        self.assertIsNotNone(result)
        self.assertEqual(result["max_404s"], 1)
        self.assertGreaterEqual(result["avg_kw_hits"], 0)
        self.assertFalse(result["should_block"])

    def test_analyze_recent_behavior_triggers_block(self):
        entries = []
        for i in range(10):
            entries.append({
                "path_lower": f"/wp-admin/{i}.php",
                "timestamp": float(i),
                "status": 404,
                "kw_check": True,
            })
        result = aiwaf_rust.analyze_recent_behavior(entries, ["wp-"])
        self.assertIsNotNone(result)
        self.assertTrue(result["should_block"])



if __name__ == "__main__":
    import unittest
    unittest.main()
