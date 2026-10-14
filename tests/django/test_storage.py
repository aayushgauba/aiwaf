#!/usr/bin/env python3
"""
Django Unit Test for Storage Simple

Simple test script to verify the keyword storage fix works.
This test doesn't require any external dependencies.
"""

import os
import sys
from unittest.mock import patch

# Setup Django
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
os.environ.setdefault('DJANGO_SETTINGS_MODULE', 'tests.test_settings')

import django
django.setup()

from tests.django.base_test import AIWAFStorageTestCase
from aiwaf.django.storage import get_keyword_store


class StorageSimpleTestCase(AIWAFStorageTestCase):
    """Test Storage Simple functionality"""
    
    def setUp(self):
        super().setUp()
    
    def test_basic_functionality(self):
        """Keyword store persists counts and returns sorted top keywords."""
        store = get_keyword_store()
        # Start clean
        for kw in store.get_all_keywords():
            store.remove_keyword(kw)

        store.add_keyword("alpha", 1)
        store.add_keyword("beta", 3)
        store.add_keyword("alpha", 2)  # alpha total should be 3

        top = store.get_top_keywords(2)
        self.assertEqual(top[0], "alpha")
        self.assertIn("beta", top)
        
        # Example patterns:
        # request = self.create_request('/test/path/')
        # response = self.process_request_through_middleware(MiddlewareClass, request)
        # self.assertEqual(response.status_code, 200)
    


if __name__ == "__main__":
    import unittest
    unittest.main()
import tempfile
from pathlib import Path

from django.test import TestCase, override_settings

from aiwaf.django import storage as django_storage
from types import SimpleNamespace
from unittest.mock import patch


class _LegacyCursor:
    def __init__(self, one=None, all_rows=None):
        self.one = one
        self.all_rows = all_rows or []
        self.executed = []

    def __enter__(self):
        return self

    def __exit__(self, *_args):
        return False

    def execute(self, sql, params=None):
        self.executed.append((sql, params))

    def fetchone(self):
        return self.one

    def fetchall(self):
        return self.all_rows


class _LegacyConnection:
    def __init__(self, cursor):
        self._cursor = cursor
        self.ops = SimpleNamespace(quote_name=lambda name: name)

    def cursor(self):
        return self._cursor


class TestAllStorageAdapters(TestCase):
    def test_legacy_schema_raw_sql_contracts(self):
        columns = {"ip_address", "reason", "reasons", "expires_at", "extended_request_info"}
        insert_cursor = _LegacyCursor(one=None)
        with patch.object(django_storage, "connection", _LegacyConnection(insert_cursor)), patch.object(
            django_storage, "_blocklist_table_columns", return_value=columns
        ):
            self.assertTrue(django_storage._blocklist_has_extended_request_info_column())
            django_storage._block_ip_legacy_schema("203.0.113.140", "test", {"path": "/"})
        self.assertTrue(any("INSERT" in sql for sql, _ in insert_cursor.executed))

        blocked_cursor = _LegacyCursor(one=(None,))
        with patch.object(django_storage, "connection", _LegacyConnection(blocked_cursor)), patch.object(
            django_storage, "_blocklist_table_columns", return_value=columns
        ):
            self.assertTrue(django_storage._is_blocked_legacy_schema("203.0.113.140"))

        delete_cursor = _LegacyCursor()
        with patch.object(django_storage, "connection", _LegacyConnection(delete_cursor)):
            django_storage._unblock_ip_legacy_schema("203.0.113.140")
        self.assertIn("DELETE", delete_cursor.executed[0][0])

        ips_cursor = _LegacyCursor(all_rows=[("203.0.113.141",)])
        with patch.object(django_storage, "connection", _LegacyConnection(ips_cursor)):
            self.assertEqual(django_storage._get_all_blocked_ips_legacy_schema(), ["203.0.113.141"])

        rows_cursor = _LegacyCursor(all_rows=[("203.0.113.141", "old", '["legacy_blacklist"]')])
        entry_columns = {"ip_address", "reason", "reasons"}
        with patch.object(django_storage, "connection", _LegacyConnection(rows_cursor)), patch.object(
            django_storage, "_blocklist_table_columns", return_value=entry_columns
        ):
            entries = django_storage._get_all_blocklist_entries_legacy_schema()
        self.assertEqual(entries[0]["reasons"], ["legacy_blacklist"])

        clear_cursor = _LegacyCursor(one=(2,))
        with patch.object(django_storage, "connection", _LegacyConnection(clear_cursor)):
            self.assertEqual(django_storage._clear_all_blocklist_entries_legacy_schema(), 2)
    def test_model_store_mutation_contracts(self):
        blocklist = django_storage.ModelBlocklistStore()
        blocklist.add_ip("203.0.113.10", "test")
        self.assertIn("203.0.113.10", blocklist.get_all_blocked_ips())
        self.assertTrue(blocklist.get_all())
        self.assertEqual(blocklist.clear_all(), 1)

        exemptions = django_storage.ModelExemptionStore()
        exemptions.add_ip("203.0.113.11", "test")
        self.assertIn("203.0.113.11", exemptions.get_all_exempted_ips())
        self.assertTrue(exemptions.get_all())
        self.assertEqual(exemptions.clear_all(), 1)

        paths = django_storage.ModelPathExemptionStore()
        paths.add_exemption("/health", "test")
        self.assertTrue(paths.is_exempted("/health"))
        self.assertTrue(paths.get_all())
        paths.remove_exemption("/health")
        paths.add_exemption("/ready", "test")
        self.assertEqual(paths.clear_all(), 1)

        keywords = django_storage.ModelKeywordStore()
        keywords.add_keyword_for_route("/", "admin", 2)
        self.assertIn("admin", keywords.get_keywords_for_route("/"))
        keywords.reset_keywords()
        self.assertEqual(keywords.get_keywords_for_route("/"), [])

    def test_feature_store_real_model_round_trip(self):
        rows = [["203.0.113.12", 4, 1, 0.2, 2, 3, 1, 0]]
        django_storage.ModelFeatureStore.persist_rows(rows)
        result = django_storage.ModelFeatureStore.get_all_data()
        self.assertEqual(len(result), 1)
        self.assertIsInstance(django_storage.get_feature_store(), django_storage.ModelFeatureStore)

    def test_csv_adapters_real_round_trip(self):
        with tempfile.TemporaryDirectory() as data_dir:
            with override_settings(AIWAF_STORAGE_MODE="csv", AIWAF_DATA_DIR=data_dir):
                django_storage._ensure_runtime_csv_backend()
                blocklist = django_storage.CSVBlocklistStoreAdapter()
                blocklist.add_ip("203.0.113.20", "test")
                self.assertTrue(blocklist.is_blocked("203.0.113.20"))
                self.assertTrue(blocklist.get_all())
                self.assertIn("203.0.113.20", blocklist.get_all_blocked_ips())
                blocklist.remove_ip("203.0.113.20")
                blocklist.block_ip("203.0.113.21", "test")
                blocklist.unblock_ip("203.0.113.21")
                blocklist.add_ip("203.0.113.22", "test")
                self.assertEqual(blocklist.clear_all(), 1)

                exemptions = django_storage.CSVExemptionStoreAdapter()
                exemptions.add_ip("203.0.113.30", "test")
                self.assertTrue(exemptions.is_exempted("203.0.113.30"))
                self.assertTrue(exemptions.get_all())
                self.assertIn("203.0.113.30", exemptions.get_all_exempted_ips())
                exemptions.remove_ip("203.0.113.30")
                exemptions.add_exemption("203.0.113.31")
                exemptions.remove_exemption("203.0.113.31")
                exemptions.add_ip("203.0.113.32")
                self.assertEqual(exemptions.clear_all(), 1)

                keywords = django_storage.CSVKeywordStoreAdapter()
                keywords.add_keyword("admin", 2)
                self.assertEqual(keywords.get_top_keywords(1), ["admin"])
                self.assertEqual(keywords.get_all_keywords(), ["admin"])
                keywords.remove_keyword("admin")
                keywords.add_keyword("login")
                keywords.reset_keywords()

                paths = django_storage.CSVPathExemptionStoreAdapter()
                paths.add_exemption("/health", "test", enabled=False)
                paths.add_exemption("/health", "test")
                self.assertTrue(paths.is_exempted("/health"))
                self.assertEqual(paths.get_all_exempted_paths(), ["/health"])
                self.assertTrue(paths.get_all())
                paths.remove_exemption("/health")
                paths.add_exemption("/ready")
                self.assertEqual(paths.clear_all(), 1)
