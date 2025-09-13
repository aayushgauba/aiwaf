#!/usr/bin/env python3
"""
Django Unit Test for AIWAF Storage System

Tests storage functionality including:
1. Keyword storage and retrieval
2. Blacklist management
3. Database operations
4. Cache integration
5. Fallback mechanisms
"""

import os
import sys
import tempfile
import json
from unittest.mock import patch, MagicMock

# Setup Django
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
os.environ.setdefault('DJANGO_SETTINGS_MODULE', 'tests.test_settings')

import django
django.setup()

from django.test import override_settings
from django.core.cache import cache
from tests.base_test import AIWAFStorageTestCase


class StorageTestCase(AIWAFStorageTestCase):
    """Test AIWAF storage functionality"""
    
    def setUp(self):
        super().setUp()
        # Import after Django setup
        from aiwaf.storage import Storage
        from aiwaf.models import BlacklistEntry, Exemption
        self.storage_class = Storage
        self.blacklist_model = BlacklistEntry
        self.exemption_model = Exemption
        
        # Clear cache before each test
        cache.clear()
    
    def test_storage_singleton_pattern(self):
        """Test that Storage follows singleton pattern"""
        storage1 = self.storage_class.get_instance()
        storage2 = self.storage_class.get_instance()
        
        self.assertIs(storage1, storage2)
    
    def test_keyword_storage_and_retrieval(self):
        """Test storing and retrieving keywords"""
        storage = self.storage_class.get_instance()
        
        # Store some keywords
        test_keywords = {
            'admin': 5,
            'login': 3,
            'api': 2,
        }
        
        for keyword, count in test_keywords.items():
            storage.store_keyword(keyword, count)
        
        # Retrieve keywords
        stored_keywords = storage.get_keywords()
        
        for keyword, count in test_keywords.items():
            self.assertIn(keyword, stored_keywords)
            self.assertEqual(stored_keywords[keyword], count)
    
    def test_blacklist_entry_creation(self):
        """Test creating blacklist entries"""
        # Create a blacklist entry
        entry = self.blacklist_model.objects.create(
            ip_address='192.168.1.100',
            reason='Suspicious activity',
            severity='HIGH'
        )
        
        self.assertEqual(entry.ip_address, '192.168.1.100')
        self.assertEqual(entry.reason, 'Suspicious activity')
        self.assertEqual(entry.severity, 'HIGH')
        self.assertTrue(entry.is_active)
    
    def test_exemption_creation(self):
        """Test creating exemptions"""
        # Create path exemption
        path_exemption = self.exemption_model.objects.create(
            exemption_type='PATH',
            value='/api/health/',
            reason='Health check endpoint'
        )
        
        # Create IP exemption
        ip_exemption = self.exemption_model.objects.create(
            exemption_type='IP',
            value='127.0.0.1',
            reason='Localhost'
        )
        
        self.assertEqual(path_exemption.exemption_type, 'PATH')
        self.assertEqual(path_exemption.value, '/api/health/')
        self.assertEqual(ip_exemption.exemption_type, 'IP')
        self.assertEqual(ip_exemption.value, '127.0.0.1')
    
    @override_settings(AIWAF_SETTINGS={'STORAGE_TYPE': 'django_cache'})
    def test_cache_storage_backend(self):
        """Test cache-based storage backend"""
        storage = self.storage_class.get_instance()
        
        # Store keyword in cache
        storage.store_keyword('test_keyword', 10)
        
        # Retrieve from cache
        keywords = storage.get_keywords()
        self.assertIn('test_keyword', keywords)
        self.assertEqual(keywords['test_keyword'], 10)
    
    @override_settings(AIWAF_SETTINGS={'STORAGE_TYPE': 'database'})
    def test_database_storage_backend(self):
        """Test database-based storage backend"""
        storage = self.storage_class.get_instance()
        
        # Store keyword in database
        storage.store_keyword('db_keyword', 15)
        
        # Retrieve from database
        keywords = storage.get_keywords()
        self.assertIn('db_keyword', keywords)
        self.assertEqual(keywords['db_keyword'], 15)
    
    def test_fallback_storage_mechanism(self):
        """Test fallback to JSON file storage"""
        with tempfile.TemporaryDirectory() as temp_dir:
            fallback_file = os.path.join(temp_dir, 'fallback_keywords.json')
            
            # Mock the fallback file path
            with patch('aiwaf.storage.Storage.FALLBACK_FILE', fallback_file):
                storage = self.storage_class.get_instance()
                
                # Simulate storage failure and fallback
                with patch.object(storage, '_store_in_cache', side_effect=Exception("Cache error")):
                    with patch.object(storage, '_store_in_database', side_effect=Exception("DB error")):
                        storage.store_keyword('fallback_keyword', 20)
                
                # Verify fallback file was created
                self.assertTrue(os.path.exists(fallback_file))
                
                # Verify content
                with open(fallback_file, 'r') as f:
                    data = json.load(f)
                    self.assertIn('fallback_keyword', data)
                    self.assertEqual(data['fallback_keyword'], 20)
    
    def test_keyword_increment(self):
        """Test incrementing existing keyword counts"""
        storage = self.storage_class.get_instance()
        
        # Store initial keyword
        storage.store_keyword('increment_test', 5)
        
        # Increment the same keyword
        storage.store_keyword('increment_test', 3)
        
        # Should be incremented, not replaced
        keywords = storage.get_keywords()
        self.assertEqual(keywords['increment_test'], 8)
    
    def test_bulk_keyword_operations(self):
        """Test bulk keyword operations for performance"""
        storage = self.storage_class.get_instance()
        
        # Store many keywords
        bulk_keywords = {f'keyword_{i}': i for i in range(100)}
        
        for keyword, count in bulk_keywords.items():
            storage.store_keyword(keyword, count)
        
        # Retrieve and verify
        stored_keywords = storage.get_keywords()
        
        for keyword, count in bulk_keywords.items():
            self.assertIn(keyword, stored_keywords)
            self.assertEqual(stored_keywords[keyword], count)
    
    def test_storage_cleanup(self):
        """Test storage cleanup functionality"""
        storage = self.storage_class.get_instance()
        
        # Store some keywords
        storage.store_keyword('temp_keyword', 1)
        
        # Cleanup storage
        storage.clear_all_keywords()
        
        # Verify cleanup
        keywords = storage.get_keywords()
        self.assertNotIn('temp_keyword', keywords)
    
    def test_concurrent_access_safety(self):
        """Test storage safety under concurrent access"""
        storage = self.storage_class.get_instance()
        
        # Simulate concurrent writes
        import threading
        
        def write_keywords(start, end):
            for i in range(start, end):
                storage.store_keyword(f'concurrent_{i}', i)
        
        # Start multiple threads
        threads = []
        for i in range(0, 50, 10):
            thread = threading.Thread(target=write_keywords, args=(i, i+10))
            threads.append(thread)
            thread.start()
        
        # Wait for all threads
        for thread in threads:
            thread.join()
        
        # Verify all keywords were stored
        keywords = storage.get_keywords()
        for i in range(50):
            self.assertIn(f'concurrent_{i}', keywords)


if __name__ == "__main__":
    import unittest
    unittest.main()