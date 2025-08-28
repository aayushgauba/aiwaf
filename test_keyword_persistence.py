#!/usr/bin/env python3
"""
Test to verify that learned keywords actually persist to the database.
This test diagnoses the keyword storage persistence issue.
"""

import os
import sys
import django
from django.conf import settings
from django.apps import apps

# Add the aiwaf directory to Python path
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

# Configure Django settings for testing
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
        SECRET_KEY='test-secret-key-for-diagnosis',
        USE_TZ=True,
    )

# Setup Django
django.setup()

def test_keyword_storage_diagnosis():
    """Diagnose the keyword storage persistence issue"""
    print("=== AIWAF Keyword Storage Diagnostic Test ===\n")
    
    # Test 1: Check if Django apps are ready and aiwaf is installed
    print("1. Checking Django app registry:")
    print(f"   Apps ready: {apps.ready}")
    print(f"   AIWAF installed: {apps.is_installed('aiwaf')}")
    print(f"   Installed apps: {[app.label for app in apps.get_app_configs()]}")
    print()
    
    # Test 2: Try importing models directly
    print("2. Testing direct model import:")
    try:
        from aiwaf.models import DynamicKeyword
        print("   ✓ Direct import successful")
    except Exception as e:
        print(f"   ✗ Direct import failed: {e}")
        return
    print()
    
    # Test 3: Check the storage module's _import_models function
    print("3. Testing storage._import_models():")
    from aiwaf.storage import _import_models, DynamicKeyword as StorageDynamicKeyword
    print(f"   Before _import_models(): DynamicKeyword = {StorageDynamicKeyword}")
    _import_models()
    # Re-import to get the updated global variable
    from aiwaf.storage import DynamicKeyword as StorageDynamicKeywordAfter
    print(f"   After _import_models(): DynamicKeyword = {StorageDynamicKeywordAfter}")
    print()
    
    # Test 4: Create database tables
    print("4. Creating database tables:")
    try:
        from django.core.management import call_command
        call_command('migrate', verbosity=0, interactive=False)
        print("   ✓ Database tables created")
    except Exception as e:
        print(f"   ✗ Migration failed: {e}")
        return
    print()
    
    # Test 5: Test keyword storage through the storage interface
    print("5. Testing keyword storage through ModelKeywordStore:")
    from aiwaf.storage import get_keyword_store
    keyword_store = get_keyword_store()
    
    # Test adding a keyword
    test_keyword = "test_malicious_keyword"
    print(f"   Adding keyword: {test_keyword}")
    keyword_store.add_keyword(test_keyword)
    
    # Verify it was stored
    print("   Checking if keyword was stored in database:")
    try:
        keyword_obj = DynamicKeyword.objects.get(keyword=test_keyword)
        print(f"   ✓ Keyword found in database: {keyword_obj.keyword} (count: {keyword_obj.count})")
    except DynamicKeyword.DoesNotExist:
        print("   ✗ Keyword NOT found in database!")
    except Exception as e:
        print(f"   ✗ Database query failed: {e}")
    print()
    
    # Test 6: Test get_top_keywords
    print("6. Testing get_top_keywords:")
    top_keywords = keyword_store.get_top_keywords(5)
    print(f"   Top keywords: {top_keywords}")
    print()
    
    print("=== Diagnostic Complete ===")

if __name__ == "__main__":
    test_keyword_storage_diagnosis()
