#!/usr/bin/env python3
"""
Comprehensive Rate Limiting Logic Checker
Tests each component of the rate limiting system individually.
"""

import os
import sys
import time
import json
from collections import defaultdict

# Add the parent directory to Python path to import aiwaf
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

def test_imports():
    """Test if all required modules can be imported"""
    print("🔍 Testing Module Imports...")
    
    results = {}
    
    # Test core Python modules
    try:
        import time
        import re
        import os
        import warnings
        from collections import defaultdict
        results['core_python'] = True
        print("   ✅ Core Python modules imported successfully")
    except Exception as e:
        results['core_python'] = False
        print(f"   ❌ Core Python import failed: {e}")
    
    # Test optional dependencies
    try:
        import numpy as np
        results['numpy'] = True
        print("   ✅ numpy imported successfully")
    except Exception as e:
        results['numpy'] = False
        print(f"   ⚠️  numpy import failed: {e}")
    
    try:
        import joblib
        results['joblib'] = True
        print("   ✅ joblib imported successfully")
    except Exception as e:
        results['joblib'] = False
        print(f"   ⚠️  joblib import failed: {e}")
    
    # Test Django modules (might fail outside Django context)
    try:
        from django.http import JsonResponse
        from django.conf import settings
        from django.core.cache import cache
        results['django_core'] = True
        print("   ✅ Django core modules imported successfully")
    except Exception as e:
        results['django_core'] = False
        print(f"   ⚠️  Django core import failed: {e} (expected outside Django)")
    
    # Test AIWAF modules
    try:
        from aiwaf.blacklist_manager import BlacklistManager
        results['blacklist_manager'] = True
        print("   ✅ BlacklistManager imported successfully")
    except Exception as e:
        results['blacklist_manager'] = False
        print(f"   ❌ BlacklistManager import failed: {e}")
    
    try:
        from aiwaf.utils import get_ip, is_exempt
        results['utils'] = True
        print("   ✅ AIWAF utils imported successfully")
    except Exception as e:
        results['utils'] = False
        print(f"   ❌ AIWAF utils import failed: {e}")
    
    return results

def test_rate_limiting_logic():
    """Test the core rate limiting logic without Django dependencies"""
    print("\n🔍 Testing Rate Limiting Logic...")
    
    # Simulate the rate limiting algorithm
    WINDOW = 10  # seconds
    MAX = 20     # soft limit
    FLOOD = 40   # hard limit
    
    # Mock cache storage
    mock_cache = {}
    
    def mock_cache_get(key, default=None):
        return mock_cache.get(key, default)
    
    def mock_cache_set(key, value, timeout=None):
        mock_cache[key] = value
    
    # Simulate rate limiting function
    def check_rate_limit(ip, current_time):
        key = f"ratelimit:{ip}"
        timestamps = mock_cache_get(key, [])
        
        # Remove old timestamps
        timestamps = [t for t in timestamps if current_time - t < WINDOW]
        
        # Add current timestamp
        timestamps.append(current_time)
        mock_cache_set(key, timestamps, timeout=WINDOW)
        
        # Check limits
        if len(timestamps) > FLOOD:
            return "FLOOD"  # Would block IP
        elif len(timestamps) > MAX:
            return "RATE_LIMITED"  # Would return 429
        else:
            return "OK"
    
    # Test scenarios
    test_ip = "192.168.1.100"
    current_time = time.time()
    
    print(f"   Testing with IP: {test_ip}")
    print(f"   Settings: WINDOW={WINDOW}s, MAX={MAX}, FLOOD={FLOOD}")
    
    # Test normal requests
    results = []
    for i in range(50):
        result = check_rate_limit(test_ip, current_time + i * 0.1)  # 10 requests per second
        results.append(result)
    
    ok_count = results.count("OK")
    rate_limited_count = results.count("RATE_LIMITED")
    flood_count = results.count("FLOOD")
    
    print(f"   📊 Results for 50 rapid requests:")
    print(f"      - OK: {ok_count}")
    print(f"      - RATE_LIMITED (429): {rate_limited_count}")
    print(f"      - FLOOD (403): {flood_count}")
    
    # Analyze results
    if ok_count > 0 and rate_limited_count > 0:
        print("   ✅ Rate limiting logic working correctly")
        return True
    else:
        print("   ❌ Rate limiting logic not working as expected")
        return False

def test_blacklist_manager():
    """Test BlacklistManager functionality"""
    print("\n🔍 Testing BlacklistManager...")
    
    try:
        from aiwaf.blacklist_manager import BlacklistManager
        
        # Check if required methods exist
        required_methods = ['block', 'is_blocked', 'unblock']
        missing_methods = []
        
        for method in required_methods:
            if not hasattr(BlacklistManager, method):
                missing_methods.append(method)
        
        if missing_methods:
            print(f"   ❌ Missing methods: {missing_methods}")
            return False
        
        print("   ✅ BlacklistManager has all required methods")
        
        # Test method signatures
        import inspect
        
        block_sig = inspect.signature(BlacklistManager.block)
        print(f"   📋 block() signature: {block_sig}")
        
        is_blocked_sig = inspect.signature(BlacklistManager.is_blocked)
        print(f"   📋 is_blocked() signature: {is_blocked_sig}")
        
        return True
        
    except Exception as e:
        print(f"   ❌ BlacklistManager test failed: {e}")
        return False

def test_storage_dependencies():
    """Test storage system dependencies"""
    print("\n🔍 Testing Storage Dependencies...")
    
    try:
        from aiwaf.storage import get_blacklist_store, get_exemption_store
        
        print("   ✅ Storage imports successful")
        
        # Test store initialization
        try:
            blacklist_store = get_blacklist_store()
            print("   ✅ Blacklist store created")
        except Exception as e:
            print(f"   ❌ Blacklist store creation failed: {e}")
            return False
        
        try:
            exemption_store = get_exemption_store()
            print("   ✅ Exemption store created")
        except Exception as e:
            print(f"   ❌ Exemption store creation failed: {e}")
            return False
        
        return True
        
    except Exception as e:
        print(f"   ❌ Storage test failed: {e}")
        return False

def analyze_middleware_code():
    """Analyze the actual middleware code for potential issues"""
    print("\n🔍 Analyzing Middleware Code...")
    
    middleware_path = os.path.join(os.path.dirname(__file__), "aiwaf", "middleware.py")
    
    try:
        with open(middleware_path, 'r', encoding='utf-8') as f:
            content = f.read()
        
        issues = []
        
        # Check for import issues
        if 'import numpy as np' in content and 'try:' not in content[:content.find('import numpy')]:
            issues.append("Hard numpy import without try/except")
        
        if 'import joblib' in content and 'try:' not in content[:content.find('import joblib')]:
            issues.append("Hard joblib import without try/except")
        
        # Check rate limiting logic
        if 'timestamps = [t for t in timestamps if now - t < self.WINDOW]' in content:
            print("   ✅ Timestamp filtering logic found")
        else:
            issues.append("Missing timestamp filtering logic")
        
        if 'len(timestamps) > self.FLOOD' in content:
            print("   ✅ Flood detection logic found")
        else:
            issues.append("Missing flood detection logic")
        
        if 'len(timestamps) > self.MAX' in content:
            print("   ✅ Rate limit detection logic found")
        else:
            issues.append("Missing rate limit detection logic")
        
        # Check exemption handling
        exemption_checks = content.count('is_exempt')
        if exemption_checks > 0:
            print(f"   ✅ Found {exemption_checks} exemption checks")
        else:
            issues.append("No exemption checks found")
        
        if issues:
            print("   ❌ Issues found:")
            for issue in issues:
                print(f"      - {issue}")
            return False
        else:
            print("   ✅ Middleware code analysis passed")
            return True
        
    except Exception as e:
        print(f"   ❌ Code analysis failed: {e}")
        return False

def suggest_fixes():
    """Suggest fixes based on the analysis"""
    print("\n🔧 Suggested Fixes:")
    
    print("\n1. Import Issues Fix:")
    print("   Add graceful imports to middleware.py:")
    print("   ```python")
    print("   try:")
    print("       import numpy as np")
    print("   except ImportError:")
    print("       np = None")
    print("   ")
    print("   try:")
    print("       import joblib")
    print("   except ImportError:")
    print("       joblib = None")
    print("   ```")
    
    print("\n2. Django Cache Check:")
    print("   Ensure cache is configured in settings.py:")
    print("   ```python")
    print("   CACHES = {")
    print("       'default': {")
    print("           'BACKEND': 'django.core.cache.backends.locmem.LocMemCache',")
    print("           'LOCATION': 'unique-snowflake',")
    print("       }")
    print("   }")
    print("   ```")
    
    print("\n3. Middleware Order:")
    print("   Ensure RateLimitMiddleware is in MIDDLEWARE list:")
    print("   ```python")
    print("   MIDDLEWARE = [")
    print("       # ... other middleware ...")
    print("       'aiwaf.middleware.RateLimitMiddleware',")
    print("       # ... rest of AIWAF middleware ...")
    print("   ]")
    print("   ```")
    
    print("\n4. Debug Rate Limiting:")
    print("   Add logging to RateLimitMiddleware:")
    print("   ```python")
    print("   import logging")
    print("   logger = logging.getLogger(__name__)")
    print("   ")
    print("   # In __call__ method:")
    print("   logger.info(f'Rate check for {ip}: {len(timestamps)} requests in window')")
    print("   ```")

def main():
    """Run comprehensive rate limiting diagnostics"""
    print("🧪 AIWAF Rate Limiting Logic Comprehensive Check")
    print("=" * 60)
    
    tests = [
        test_imports,
        test_rate_limiting_logic,
        test_blacklist_manager,
        test_storage_dependencies,
        analyze_middleware_code
    ]
    
    passed = 0
    total = len(tests)
    
    for test in tests:
        try:
            if test():
                passed += 1
        except Exception as e:
            print(f"❌ Test {test.__name__} failed with exception: {e}")
    
    print("\n" + "=" * 60)
    print(f"📊 Diagnostic Results: {passed}/{total} checks passed")
    
    if passed < total:
        suggest_fixes()
    else:
        print("\n🎉 All checks passed! Rate limiting logic appears correct.")
        print("\nIf rate limiting still isn't working, check:")
        print("   1. Django server is running")
        print("   2. Middleware is properly configured")
        print("   3. Your IP isn't exempted")
        print("   4. Cache is working correctly")

if __name__ == "__main__":
    main()
