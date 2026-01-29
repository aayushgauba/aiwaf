#!/usr/bin/env python3
"""
Integration tests for the Rust feature extraction helper.
Skips automatically if the aiwaf_rust extension is missing.
"""

import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from django.test import TestCase

try:
    import aiwaf_rust
except Exception:
    aiwaf_rust = None


class RustFeatureExtractionTests(TestCase):
    @classmethod
    def setUpClass(cls):
        super().setUpClass()
        if aiwaf_rust is None:
            raise AssertionError(
                "aiwaf_rust extension not available. Build it with: "
                "maturin develop -m Cargo.toml"
            )

    def test_extract_features_basic_fields(self):
        records = [
            {
                "ip": "1.1.1.1",
                "path_lower": "/.env",
                "path_len": 5,
                "timestamp": 1_000.0,
                "response_time": 0.25,
                "status_idx": 2,
                "kw_check": True,
                "total_404": 3,
            }
        ]
        features = aiwaf_rust.extract_features(records, [".env", "wp-"])
        self.assertEqual(len(features), 1)
        feature = features[0]
        self.assertEqual(feature["ip"], "1.1.1.1")
        self.assertEqual(feature["path_len"], 5)
        self.assertEqual(feature["resp_time"], 0.25)
        self.assertEqual(feature["status_idx"], 2)
        self.assertEqual(feature["total_404"], 3)
        self.assertEqual(feature["kw_hits"], 1)
        self.assertEqual(feature["burst_count"], 1)

    def test_extract_features_burst_and_kw_flags(self):
        records = [
            {
                "ip": "2.2.2.2",
                "path_lower": "/wp-login.php",
                "path_len": 13,
                "timestamp": 2_000.0,
                "response_time": 0.5,
                "status_idx": 1,
                "kw_check": True,
                "total_404": 0,
            },
            {
                "ip": "2.2.2.2",
                "path_lower": "/wp-admin/install.php",
                "path_len": 22,
                "timestamp": 2_005.0,
                "response_time": 0.6,
                "status_idx": 1,
                "kw_check": True,
                "total_404": 0,
            },
            {
                "ip": "2.2.2.2",
                "path_lower": "/legit",
                "path_len": 6,
                "timestamp": 2_100.0,
                "response_time": 0.4,
                "status_idx": 0,
                "kw_check": False,
                "total_404": 0,
            },
        ]
        features = aiwaf_rust.extract_features(records, ["wp-", "admin"])
        self.assertEqual(len(features), 3)

        first, second, third = features
        self.assertEqual(first["burst_count"], 1)
        self.assertGreaterEqual(second["burst_count"], 2)
        self.assertEqual(third["burst_count"], 1)
        self.assertEqual(first["kw_hits"], 1)
        self.assertEqual(second["kw_hits"], 2)
        self.assertEqual(third["kw_hits"], 0)

    def test_extract_features_empty_input(self):
        self.assertEqual(aiwaf_rust.extract_features([], ["foo"]), [])


if __name__ == "__main__":
    import unittest

    unittest.main()
