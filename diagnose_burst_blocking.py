#!/usr/bin/env python3
"""
AIWAF IP Blocking Diagnostics
Diagnose why burst requests might not be getting blocked.
"""

import os
import sys

# Add the parent directory to Python path to import aiwaf
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

def check_middleware_configuration():
    """Check if rate limiting middleware is properly configured"""
    print("🔍 Checking Middleware Configuration...")
    
    # Check middleware.py for available classes
    middleware_path = os.path.join(os.path.dirname(__file__), "aiwaf", "middleware.py")
    try:
        with open(middleware_path, 'r', encoding='utf-8') as f:
            content = f.read()
        
        # Check for different middleware classes
        available_middleware = []
        if 'class IPAndKeywordBlockMiddleware' in content:
            available_middleware.append('IPAndKeywordBlockMiddleware')
        if 'class RateLimitMiddleware' in content:
            available_middleware.append('RateLimitMiddleware')
        if 'class AIAnomalyMiddleware' in content:
            available_middleware.append('AIAnomalyMiddleware')
        if 'class KeywordLearningMiddleware' in content:
            available_middleware.append('KeywordLearningMiddleware')
        
        print(f"✅ Available middleware classes: {available_middleware}")
        
        if 'RateLimitMiddleware' not in available_middleware:
            print("❌ ISSUE: RateLimitMiddleware not found!")
            return False
        
        return True
        
    except Exception as e:
        print(f"❌ Error checking middleware: {e}")
        return False

def check_rate_limiting_logic():
    """Check the rate limiting logic implementation"""
    print("\n🔍 Checking Rate Limiting Logic...")
    
    middleware_path = os.path.join(os.path.dirname(__file__), "aiwaf", "middleware.py")
    try:
        with open(middleware_path, 'r', encoding='utf-8') as f:
            content = f.read()
        
        # Check for rate limiting settings
        rate_settings = []
        if 'AIWAF_RATE_WINDOW' in content:
            rate_settings.append('AIWAF_RATE_WINDOW (default: 10 seconds)')
        if 'AIWAF_RATE_MAX' in content:
            rate_settings.append('AIWAF_RATE_MAX (soft limit, default: 20)')
        if 'AIWAF_RATE_FLOOD' in content:
            rate_settings.append('AIWAF_RATE_FLOOD (hard limit, default: 40)')
        
        if rate_settings:
            print("✅ Rate limiting settings found:")
            for setting in rate_settings:
                print(f"   - {setting}")
        else:
            print("❌ ISSUE: No rate limiting settings found!")
            return False
        
        # Check for blocking logic
        if 'BlacklistManager.block(ip, "Flood pattern")' in content:
            print("✅ Flood pattern blocking logic found")
        else:
            print("❌ ISSUE: Flood pattern blocking logic missing!")
            return False
        
        # Check for cache usage
        if 'cache.get(key, [])' in content and 'cache.set(key, timestamps' in content:
            print("✅ Cache-based request tracking found")
        else:
            print("❌ ISSUE: Cache-based request tracking missing!")
            return False
        
        return True
        
    except Exception as e:
        print(f"❌ Error checking rate limiting logic: {e}")
        return False

def check_blacklist_manager():
    """Check if BlacklistManager is working correctly"""
    print("\n🔍 Checking BlacklistManager...")
    
    try:
        # Try to import BlacklistManager
        from aiwaf.blacklist_manager import BlacklistManager
        print("✅ BlacklistManager imported successfully")
        
        # Check if it has required methods
        required_methods = ['block', 'is_blocked', 'unblock']
        missing_methods = []
        
        for method in required_methods:
            if not hasattr(BlacklistManager, method):
                missing_methods.append(method)
        
        if missing_methods:
            print(f"❌ ISSUE: BlacklistManager missing methods: {missing_methods}")
            return False
        else:
            print("✅ BlacklistManager has all required methods")
        
        return True
        
    except Exception as e:
        print(f"❌ Error checking BlacklistManager: {e}")
        return False

def check_exemption_system():
    """Check if IP exemption system might be interfering"""
    print("\n🔍 Checking Exemption System...")
    
    try:
        # Check for exemption logic in middleware
        middleware_path = os.path.join(os.path.dirname(__file__), "aiwaf", "middleware.py")
        with open(middleware_path, 'r', encoding='utf-8') as f:
            content = f.read()
        
        exemption_checks = []
        if 'is_exempt(request)' in content:
            exemption_checks.append('is_exempt(request) - Path-based exemptions')
        if 'exemption_store.is_exempted(ip)' in content:
            exemption_checks.append('exemption_store.is_exempted(ip) - IP-based exemptions')
        if 'is_exempt_path(' in content:
            exemption_checks.append('is_exempt_path() - Enhanced path exemptions')
        
        if exemption_checks:
            print("✅ Exemption checks found:")
            for check in exemption_checks:
                print(f"   - {check}")
            print("⚠️  WARNING: If your IP is exempted, rate limiting won't work!")
        else:
            print("❌ ISSUE: No exemption system found!")
        
        return True
        
    except Exception as e:
        print(f"❌ Error checking exemption system: {e}")
        return False

def generate_configuration_fix():
    """Generate the correct middleware configuration"""
    print("\n🔧 Recommended Configuration Fix...")
    
    print("Add RateLimitMiddleware to your Django settings.py:")
    print()
    print("MIDDLEWARE = [")
    print("    'django.middleware.security.SecurityMiddleware',")
    print("    'django.contrib.sessions.middleware.SessionMiddleware',")
    print("    'django.middleware.common.CommonMiddleware',")
    print("    'django.middleware.csrf.CsrfViewMiddleware',")
    print("    ")
    print("    # AIWAF Middleware (add these)")
    print("    'aiwaf.middleware.RateLimitMiddleware',           # ⭐ ADD THIS for burst protection")
    print("    'aiwaf.middleware.IPAndKeywordBlockMiddleware',    # Basic protection")
    print("    'aiwaf.middleware.AIAnomalyMiddleware',            # AI anomaly detection")
    print("    'aiwaf.middleware.KeywordLearningMiddleware',      # Learning middleware")
    print("    ")
    print("    'django.contrib.auth.middleware.AuthenticationMiddleware',")
    print("    'django.contrib.messages.middleware.MessageMiddleware',")
    print("    'django.middleware.clickjacking.XFrameOptionsMiddleware',")
    print("]")
    print()
    print("Optional rate limiting settings:")
    print("AIWAF_RATE_WINDOW = 10    # Time window in seconds")
    print("AIWAF_RATE_MAX = 20       # Soft limit (429 response)")
    print("AIWAF_RATE_FLOOD = 40     # Hard limit (403 + IP block)")
    print()

def check_cache_configuration():
    """Check if Django cache is properly configured"""
    print("\n🔍 Checking Cache Configuration...")
    
    print("⚠️  RateLimitMiddleware requires Django cache to be configured.")
    print("Add this to your settings.py if not already present:")
    print()
    print("CACHES = {")
    print("    'default': {")
    print("        'BACKEND': 'django.core.cache.backends.locmem.LocMemCache',")
    print("        'LOCATION': 'unique-snowflake',")
    print("    }")
    print("}")
    print()
    print("Or for production with Redis:")
    print("CACHES = {")
    print("    'default': {")
    print("        'BACKEND': 'django.core.cache.backends.redis.RedisCache',")
    print("        'LOCATION': 'redis://127.0.0.1:6379/1',")
    print("    }")
    print("}")

def main():
    """Run diagnostics for IP blocking burst protection"""
    print("🧪 AIWAF IP Blocking Burst Protection Diagnostics")
    print("=" * 60)
    
    tests = [
        check_middleware_configuration,
        check_rate_limiting_logic,
        check_blacklist_manager,
        check_exemption_system
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
        print("\n🚨 LIKELY ISSUES FOUND:")
        if passed == 0:
            print("   - RateLimitMiddleware may not be included in MIDDLEWARE setting")
        print("   - Check that RateLimitMiddleware is in your Django MIDDLEWARE list")
        print("   - Verify Django cache is configured")
        print("   - Check if your IP is exempted from blocking")
        
        generate_configuration_fix()
        check_cache_configuration()
    else:
        print("\n✅ All checks passed! Rate limiting should be working.")
        print("If bursts still aren't blocked, check:")
        print("   1. Your IP might be in exemption list")
        print("   2. Rate limits might be too high for your test")
        print("   3. Cache might not be persistent between requests")

if __name__ == "__main__":
    main()
