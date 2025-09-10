#!/usr/bin/env python3
"""
Debug test to check if keyword storage works in different phases of middleware processing.
This will test if Django models are available during process_request vs process_response.
"""

import os
import sys
import django
from django.conf import settings

# Mock Django setup
if not settings.configured:
    settings.configure(
        DEBUG=True,
        DATABASES={
            'default': {
                'ENGINE': 'django.db.backends.sqlite3',
                'NAME': ':memory:',
            }
        },
        INSTALLED_APPS=[
            'django.contrib.contenttypes',
            'django.contrib.auth',
            'aiwaf',
        ],
        SECRET_KEY='test-secret-key',
    )
    django.setup()

def test_keyword_storage_access():
    """Test if keyword storage works properly"""
    print("🔧 Testing Keyword Storage Access")
    print("=" * 50)
    
    # Test 1: Basic model import
    print("\n1. Testing model imports...")
    try:
        from aiwaf.models import DynamicKeyword
        print("   ✅ DynamicKeyword model imported successfully")
    except Exception as e:
        print(f"   ❌ Failed to import DynamicKeyword: {e}")
        return
    
    # Test 2: Create database tables
    print("\n2. Creating database tables...")
    try:
        from django.core.management import call_command
        call_command('migrate', verbosity=0, interactive=False)
        print("   ✅ Database tables created successfully")
    except Exception as e:
        print(f"   ❌ Failed to create tables: {e}")
        return
    
    # Test 3: Test keyword storage directly
    print("\n3. Testing direct keyword storage...")
    try:
        from aiwaf.storage import get_keyword_store
        keyword_store = get_keyword_store()
        
        # Test adding a keyword
        test_keyword = "testmalicious"
        print(f"   Adding keyword: {test_keyword}")
        keyword_store.add_keyword(test_keyword)
        print("   ✅ Keyword added successfully")
        
        # Test retrieving keywords
        top_keywords = keyword_store.get_top_keywords(5)
        print(f"   Top keywords: {top_keywords}")
        
        if test_keyword in top_keywords:
            print("   ✅ Keyword retrieved successfully")
        else:
            print("   ❌ Keyword not found in top keywords")
            
    except Exception as e:
        print(f"   ❌ Failed to test keyword storage: {e}")
        import traceback
        traceback.print_exc()
        return
    
    # Test 4: Simulate middleware context
    print("\n4. Testing in middleware-like context...")
    try:
        from django.http import HttpRequest, HttpResponse
        from django.test import RequestFactory
        
        # Create mock request
        factory = RequestFactory()
        request = factory.get('/malicious/wp-admin/test.php')
        
        print("   Simulating process_request context...")
        # This simulates what happens in IPAndKeywordBlockMiddleware.process_request
        keyword_store = get_keyword_store()
        test_keyword_2 = "wpadmin"
        keyword_store.add_keyword(test_keyword_2)
        print(f"   ✅ Added keyword '{test_keyword_2}' in process_request context")
        
        print("   Simulating process_response context...")
        # This simulates what happens in AIAnomalyMiddleware.process_response
        response = HttpResponse(status=404)
        test_keyword_3 = "configphp"
        keyword_store.add_keyword(test_keyword_3)
        print(f"   ✅ Added keyword '{test_keyword_3}' in process_response context")
        
        # Check if both keywords were stored
        all_keywords = keyword_store.get_top_keywords(10)
        print(f"   All keywords: {all_keywords}")
        
        missing_keywords = []
        for kw in [test_keyword, test_keyword_2, test_keyword_3]:
            if kw not in all_keywords:
                missing_keywords.append(kw)
        
        if missing_keywords:
            print(f"   ❌ Missing keywords: {missing_keywords}")
        else:
            print("   ✅ All keywords stored successfully")
            
    except Exception as e:
        print(f"   ❌ Failed middleware context test: {e}")
        import traceback
        traceback.print_exc()
        return
    
    # Test 5: Check fallback storage
    print("\n5. Checking fallback storage...")
    try:
        fallback_file = os.path.join(os.path.dirname(__file__), 'aiwaf', 'fallback_keywords.json')
        if os.path.exists(fallback_file):
            import json
            with open(fallback_file, 'r') as f:
                fallback_data = json.load(f)
            print(f"   Fallback storage content: {fallback_data}")
        else:
            print("   No fallback storage file found")
    except Exception as e:
        print(f"   ❌ Failed to check fallback storage: {e}")
    
    print(f"\n🎉 Keyword Storage Test Complete!")

def test_middleware_learning_conditions():
    """Test the specific conditions under which middlewares learn keywords"""
    print("\n" + "="*50)
    print("🧪 Testing Middleware Learning Conditions")
    print("="*50)
    
    from django.test import RequestFactory
    from aiwaf.trainer import path_exists_in_django
    from aiwaf.storage import get_keyword_store
    
    factory = RequestFactory()
    keyword_store = get_keyword_store()
    
    # Test scenarios
    test_cases = [
        ("/wp-admin/admin.php", "Should learn (non-existent malicious path)"),
        ("/admin/", "Might not learn (could be legitimate)"),
        ("/config/database.yml", "Should learn (config file access)"),
        ("/.env", "Should learn (env file access)"),
        ("/legitimate/page/", "Should not learn (if legitimate)"),
    ]
    
    print("\nTesting learning conditions:")
    
    for path, description in test_cases:
        request = factory.get(path)
        path_exists = path_exists_in_django(path)
        
        print(f"\n   Path: {path}")
        print(f"   Description: {description}")
        print(f"   Path exists in Django: {path_exists}")
        
        # Test IPAndKeywordBlockMiddleware condition
        if not path_exists:
            print("   ✅ IPAndKeywordBlockMiddleware would attempt to learn")
        else:
            print("   ❌ IPAndKeywordBlockMiddleware would NOT learn (path exists)")
        
        # Test AIAnomalyMiddleware condition (needs 404 response)
        print("   ℹ️  AIAnomalyMiddleware would learn only with 404 response")

if __name__ == "__main__":
    test_keyword_storage_access()
    test_middleware_learning_conditions()
