#!/usr/bin/env python3
"""
Django Unit Test for Csv Simple

Simple CSV Test Script
Test AI-WAF CSV functionality outside of Django
"""

import os
import sys
import csv
import tempfile

# Setup Django
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
os.environ.setdefault('DJANGO_SETTINGS_MODULE', 'tests.test_settings')

import django
django.setup()

from tests.base_test import AIWAFTestCase
from aiwaf import trainer


class CsvSimpleTestCase(AIWAFTestCase):
    """Test Csv Simple functionality"""
    
    def setUp(self):
        super().setUp()
    
    def test_csv_operations(self):
        """Trainer CSV reader turns log rows into Apache-style strings."""
        fieldnames = [
            "timestamp", "ip", "method", "path", "status_code",
            "content_length", "referer", "user_agent", "response_time"
        ]
        rows = [
            {
                "timestamp": "2025-01-01T12:00:00",
                "ip": "203.0.113.10",
                "method": "GET",
                "path": "/login/",
                "status_code": "200",
                "content_length": "1234",
                "referer": "https://example.com/",
                "user_agent": "Mozilla/5.0",
                "response_time": "0.10",
            },
            {
                "timestamp": "2025-01-01T12:00:01",
                "ip": "203.0.113.11",
                "method": "POST",
                "path": "/api/push/",
                "status_code": "403",
                "content_length": "0",
                "referer": "-",
                "user_agent": "curl/8.0",
                "response_time": "0.30",
            },
        ]
        with tempfile.NamedTemporaryFile("w", newline="", delete=False, suffix=".csv") as tmp:
            writer = csv.DictWriter(tmp, fieldnames=fieldnames)
            writer.writeheader()
            writer.writerows(rows)
            csv_path = tmp.name
        try:
            lines = trainer._read_csv_logs(csv_path)
        finally:
            os.remove(csv_path)
        
        self.assertEqual(len(lines), 2)
        self.assertIn('GET /login/', lines[0])
        self.assertIn('POST /api/push/', lines[1])
    


if __name__ == "__main__":
    import unittest
    unittest.main()
