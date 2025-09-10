#!/usr/bin/env python3
"""
Test script to demonstrate the keyword storage persistence fix.
This simulates the middleware behavior without requiring Django.
"""

import os
import sys
import json
from unittest.mock import Mock, patch

# Add the aiwaf directory to Python path
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

def test_keyword_storage_without_django():
    """Test keyword storage when Django models are unavailable"""
    print("=== Testing Keyword Storage Without Django ===\n")
    
    # Clean up any existing fallback file
    fallback_path = os.path.join(os.path.dirname(__file__), 'aiwaf', 'fallback_keywords.json')
    if os.path.exists(fallback_path):
        os.remove(fallback_path)
        print("Cleaned up existing fallback file")
    
    # Mock Django to be unavailable
    with patch.dict(sys.modules, {'django': None, 'django.apps': None, 'django.conf': None}):
        print("1. Testing with Django unavailable:")
        
        # Import the storage module (this should not fail)
        try:
            from aiwaf.storage import get_keyword_store
            print("   ✓ Storage module imported successfully")
        except Exception as e:
            print(f"   ✗ Storage import failed: {e}")
            return
        
        # Get the keyword store
        keyword_store = get_keyword_store()
        print("   ✓ Keyword store instance created")
        
        # Test adding keywords (should use fallback storage)
        print("\n2. Testing keyword addition:")
        test_keywords = ['malicious_test', 'attack_pattern', 'vulnerability_scan']
        
        for keyword in test_keywords:
            print(f"   Adding keyword: {keyword}")
            keyword_store.add_keyword(keyword, count=1)
        
        # Check if fallback file was created
        if os.path.exists(fallback_path):
            print("   ✓ Fallback storage file created")
            
            # Read and display the stored keywords
            with open(fallback_path, 'r') as f:
                stored_data = json.load(f)
            print(f"   ✓ Stored keywords: {stored_data}")
        else:
            print("   ✗ Fallback storage file not created")
            return
        
        # Test getting top keywords
        print("\n3. Testing keyword retrieval:")
        top_keywords = keyword_store.get_top_keywords(5)
        print(f"   Top keywords: {top_keywords}")
        
        if set(test_keywords).issubset(set(top_keywords)):
            print("   ✓ All test keywords retrieved successfully")
        else:
            print("   ⚠ Some keywords missing from retrieval")
        
        # Test adding more counts to existing keywords
        print("\n4. Testing keyword count updates:")
        keyword_store.add_keyword('malicious_test', count=5)
        
        with open(fallback_path, 'r') as f:
            updated_data = json.load(f)
        print(f"   Updated counts: {updated_data}")
        
        if updated_data.get('malicious_test', 0) == 6:  # 1 + 5
            print("   ✓ Keyword count updated correctly")
        else:
            print("   ✗ Keyword count not updated correctly")
    
    print("\n=== Test Complete ===")
    
    # Cleanup
    if os.path.exists(fallback_path):
        os.remove(fallback_path)
        print("✓ Cleaned up test files")

def test_middleware_integration():
    """Test that middleware can use the storage without issues"""
    print("\n=== Testing Middleware Integration ===\n")
    
    # Mock a request object
    class MockRequest:
        def __init__(self, path):
            self.path = path
            self.method = 'GET'
            self.META = {'REMOTE_ADDR': '192.168.1.100'}
    
    # Test with fallback storage
    with patch.dict(sys.modules, {'django': None, 'django.apps': None, 'django.conf': None}):
        try:
            from aiwaf.storage import get_keyword_store
            keyword_store = get_keyword_store()
            
            # Simulate middleware learning from malicious requests
            malicious_paths = [
                '/wp-admin/admin-ajax.php',
                '/administrator/index.php', 
                '/.env',
                '/config/database.yml'
            ]
            
            print("Simulating middleware keyword learning:")
            for path in malicious_paths:
                # Extract segments like middleware would
                import re
                segments = [seg for seg in re.split(r"\W+", path.lower()) if len(seg) > 3]
                
                print(f"   Path: {path}")
                print(f"   Segments: {segments}")
                
                for seg in segments:
                    keyword_store.add_keyword(seg)
                print()
            
            # Get learned keywords
            learned_keywords = keyword_store.get_top_keywords(10)
            print(f"Learned keywords: {learned_keywords}")
            
            expected_keywords = ['admin', 'ajax', 'administrator', 'index', 'config', 'database']
            found_keywords = [k for k in expected_keywords if k in learned_keywords]
            
            print(f"Expected keywords found: {found_keywords}")
            if len(found_keywords) >= 4:
                print("✓ Middleware integration working correctly")
            else:
                print("⚠ Some expected keywords not learned")
                
        except Exception as e:
            print(f"✗ Middleware integration test failed: {e}")

if __name__ == "__main__":
    test_keyword_storage_without_django()
    test_middleware_integration()
