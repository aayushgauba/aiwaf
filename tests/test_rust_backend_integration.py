#!/usr/bin/env python3
"""
Integration tests for the Rust backend (real extension module).
Skips if aiwaf_rust isn't available.
"""

import os
import sys

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



if __name__ == "__main__":
    import unittest
    unittest.main()
