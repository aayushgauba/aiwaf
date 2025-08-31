#!/usr/bin/env python3
"""
Django-specific rate limiting test to identify configuration issues.
"""

import os
import sys

# Add the parent directory to Python path to import aiwaf
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

def test_django_integration():
    """Test Django-specific components of rate limiting"""
    print("🔍 Testing Django Integration Issues")
    print("=" * 50)
    
    # Test 1: Import the middleware
    print("1. Testing middleware import...")
    try:
        from aiwaf.middleware import RateLimitMiddleware
        print("   ✅ RateLimitMiddleware imported successfully")
    except Exception as e:
        print(f"   ❌ FAILED to import RateLimitMiddleware: {e}")
        return False
    
    # Test 2: Check required functions
    print("\n2. Testing required functions...")
    try:
        from aiwaf.utils import is_exempt, get_ip
        print("   ✅ is_exempt and get_ip imported successfully")
    except Exception as e:
        print(f"   ❌ FAILED to import utils: {e}")
        return False
    
    # Test 3: Check storage components
    print("\n3. Testing storage components...")
    try:
        from aiwaf.storage import get_exemption_store
        exemption_store = get_exemption_store()
        print("   ✅ Exemption store created successfully")
        print(f"   📋 Store type: {type(exemption_store)}")
    except Exception as e:
        print(f"   ❌ FAILED to create exemption store: {e}")
        return False
    
    # Test 4: Check BlacklistManager
    print("\n4. Testing BlacklistManager...")
    try:
        from aiwaf.blacklist_manager import BlacklistManager
        print("   ✅ BlacklistManager imported successfully")
        
        # Check required methods
        required_methods = ['block', 'is_blocked']
        for method in required_methods:
            if hasattr(BlacklistManager, method):
                print(f"   ✅ {method}() method exists")
            else:
                print(f"   ❌ {method}() method missing")
                return False
                
    except Exception as e:
        print(f"   ❌ FAILED to import BlacklistManager: {e}")
        return False
    
    # Test 5: Mock Django components
    print("\n5. Testing Django mock setup...")
    try:
        # Mock Django settings
        import types
        settings = types.ModuleType('settings')
        settings.AIWAF_RATE_WINDOW = 10
        settings.AIWAF_RATE_MAX = 20
        settings.AIWAF_RATE_FLOOD = 40
        
        # Mock Django cache
        class MockCache:
            def __init__(self):
                self.data = {}
            def get(self, key, default=None):
                return self.data.get(key, default)
            def set(self, key, value, timeout=None):
                self.data[key] = value
                
        cache = MockCache()
        
        # Mock request
        class MockRequest:
            def __init__(self, path="/test", meta=None):
                self.path = path
                self.META = meta or {'REMOTE_ADDR': '192.168.1.100'}
        
        print("   ✅ Django mocks created successfully")
        
        return True
        
    except Exception as e:
        print(f"   ❌ FAILED to create Django mocks: {e}")
        return False

def test_middleware_instantiation():
    """Test if middleware can be properly instantiated"""
    print("\n🔍 Testing Middleware Instantiation")
    print("=" * 40)
    
    try:
        # Mock Django settings temporarily
        import types
        settings_module = types.ModuleType('settings')
        settings_module.AIWAF_RATE_WINDOW = 10
        settings_module.AIWAF_RATE_MAX = 20
        settings_module.AIWAF_RATE_FLOOD = 40
        
        # Add to sys.modules
        sys.modules['django.conf.settings'] = settings_module
        sys.modules['django.conf'] = types.ModuleType('django.conf')
        sys.modules['django.conf'].settings = settings_module
        
        # Mock get_response function
        def mock_get_response(request):
            return {"status": "ok"}
        
        # Try to instantiate middleware
        from aiwaf.middleware import RateLimitMiddleware
        middleware = RateLimitMiddleware(mock_get_response)
        
        print(f"   ✅ Middleware instantiated successfully")
        print(f"   📋 Window: {middleware.WINDOW} seconds")
        print(f"   📋 Max: {middleware.MAX} requests")
        print(f"   📋 Flood: {middleware.FLOOD} requests")
        
        # Clean up
        if 'django.conf.settings' in sys.modules:
            del sys.modules['django.conf.settings']
        if 'django.conf' in sys.modules:
            del sys.modules['django.conf']
        
        return True
        
    except Exception as e:
        print(f"   ❌ FAILED to instantiate middleware: {e}")
        import traceback
        traceback.print_exc()
        return False

def check_common_issues():
    """Check for common configuration issues"""
    print("\n🔍 Checking Common Configuration Issues")
    print("=" * 45)
    
    issues_found = []
    
    # Check 1: Middleware order in settings guide
    print("1. Checking settings guide middleware order...")
    try:
        settings_path = os.path.join(os.path.dirname(__file__), "AIWAF_SETTINGS_GUIDE.py")
        with open(settings_path, 'r', encoding='utf-8') as f:
            content = f.read()
        
        if 'RateLimitMiddleware' in content:
            print("   ✅ RateLimitMiddleware found in settings guide")
        else:
            print("   ❌ RateLimitMiddleware missing from settings guide")
            issues_found.append("RateLimitMiddleware not in settings guide")
            
        # Check order
        lines = content.split('\n')
        middleware_lines = [line for line in lines if 'middleware.' in line.lower()]
        rate_limit_line = next((i for i, line in enumerate(middleware_lines) if 'RateLimitMiddleware' in line), -1)
        
        if rate_limit_line >= 0:
            print(f"   📋 RateLimitMiddleware position: {rate_limit_line + 1} in middleware list")
            if rate_limit_line > 2:  # Should be early in the list
                print("   ⚠️  WARNING: RateLimitMiddleware should be earlier in middleware list")
        
    except Exception as e:
        print(f"   ❌ Error checking settings guide: {e}")
        issues_found.append(f"Cannot read settings guide: {e}")
    
    # Check 2: Cache configuration
    print("\n2. Checking cache configuration examples...")
    try:
        if 'CACHES' in content:
            print("   ✅ Cache configuration found in settings guide")
        else:
            print("   ❌ Cache configuration missing from settings guide")
            issues_found.append("Cache configuration not documented")
    except:
        pass
    
    # Check 3: Dependencies
    print("\n3. Checking potential dependency conflicts...")
    
    # Try importing time (should always work)
    try:
        import time
        print("   ✅ time module available")
    except Exception as e:
        print(f"   ❌ time module issue: {e}")
        issues_found.append("time module not available")
    
    print(f"\n📊 Issues found: {len(issues_found)}")
    for issue in issues_found:
        print(f"   - {issue}")
    
    return len(issues_found) == 0

def main():
    """Run all Django integration tests"""
    print("🧪 AIWAF Rate Limiting Django Integration Test")
    print("=" * 60)
    
    tests = [
        test_django_integration,
        test_middleware_instantiation,
        check_common_issues
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
    print(f"📊 Test Results: {passed}/{total} tests passed")
    
    if passed == total:
        print("\n🎉 All Django integration tests passed!")
        print("\n💡 If rate limiting still doesn't work:")
        print("   1. Check your Django MIDDLEWARE setting includes RateLimitMiddleware")
        print("   2. Verify Django cache is configured and working")
        print("   3. Test with a fresh IP (not exempted)")
        print("   4. Check Django logs for any errors")
        print("   5. Restart Django server after configuration changes")
    else:
        print("\n⚠️  Some integration tests failed.")
        print("   Fix the issues above before testing rate limiting.")
    
    return passed == total

if __name__ == "__main__":
    success = main()
    sys.exit(0 if success else 1)
