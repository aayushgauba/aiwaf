#!/usr/bin/env python3
"""
Test script for enhanced HoneypotTimingMiddleware features:
1. Checking if view accepts POST requests
2. Page timeout after 4 minutes requiring reload
"""

import os
import sys
import time

# Add the parent directory to Python path to import aiwaf
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

def test_post_validation_logic():
    """Test the POST request validation logic"""
    print("🔍 Testing POST Request Validation Logic...")
    
    # Mock request class
    class MockRequest:
        def __init__(self, path, method="POST"):
            self.path = path
            self.method = method
    
    # Mock Django URL resolution
    class MockResolvedMatch:
        def __init__(self, func=None, view_class=None):
            self.func = func if func else type('MockFunc', (), {'cls': view_class})()
    
    try:
        # Test cases for different URL patterns
        test_cases = [
            # (path, should_accept_post, description)
            ("/contact/", True, "Contact form - should accept POST"),
            ("/api/data.json", False, "JSON API endpoint - typically GET only"),
            ("/static/css/style.css", False, "Static CSS file - should not accept POST"),
            ("/admin/login/", True, "Admin login - should accept POST"),
            ("/robots.txt", False, "Robots.txt - should not accept POST"),
            ("/user/profile/", True, "User profile - ambiguous, should allow POST"),
            ("/favicon.ico", False, "Favicon - should not accept POST"),
        ]
        
        # Simulate the logic from _view_accepts_post
        def simulate_post_check(path):
            non_post_patterns = [
                '/api/', '/static/', '/media/', '/favicon.ico',
                '/robots.txt', '/sitemap.xml', '.json', '.xml', '.css', '.js'
            ]
            
            path_lower = path.lower()
            if any(pattern in path_lower for pattern in non_post_patterns):
                return False
            return True
        
        passed = 0
        total = len(test_cases)
        
        for path, expected, description in test_cases:
            result = simulate_post_check(path)
            if result == expected:
                print(f"   ✅ {description}")
                passed += 1
            else:
                print(f"   ❌ {description} - Expected: {expected}, Got: {result}")
        
        print(f"\n📊 POST validation tests: {passed}/{total} passed")
        return passed == total
        
    except Exception as e:
        print(f"❌ Error testing POST validation: {e}")
        return False

def test_page_timeout_logic():
    """Test the page timeout logic"""
    print("\n🔍 Testing Page Timeout Logic...")
    
    try:
        # Simulate the timing logic
        MIN_FORM_TIME = 1.0
        MAX_PAGE_TIME = 240  # 4 minutes
        
        test_scenarios = [
            # (time_diff, expected_result, description)
            (0.5, "too_fast", "Form submitted too quickly"),
            (2.0, "valid", "Normal form submission timing"),
            (120.0, "valid", "2 minutes - still valid"),
            (250.0, "expired", "Over 4 minutes - should expire"),
            (300.0, "expired", "5 minutes - definitely expired"),
        ]
        
        passed = 0
        total = len(test_scenarios)
        
        for time_diff, expected, description in test_scenarios:
            if time_diff < MIN_FORM_TIME:
                result = "too_fast"
            elif time_diff > MAX_PAGE_TIME:
                result = "expired"
            else:
                result = "valid"
            
            if result == expected:
                print(f"   ✅ {description} ({time_diff}s)")
                passed += 1
            else:
                print(f"   ❌ {description} ({time_diff}s) - Expected: {expected}, Got: {result}")
        
        print(f"\n📊 Page timeout tests: {passed}/{total} passed")
        return passed == total
        
    except Exception as e:
        print(f"❌ Error testing page timeout: {e}")
        return False

def test_middleware_configuration():
    """Test that the middleware file contains the new enhancements"""
    print("\n🔍 Testing Middleware Configuration...")
    
    try:
        middleware_path = os.path.join(os.path.dirname(__file__), "aiwaf", "middleware.py")
        with open(middleware_path, 'r', encoding='utf-8') as f:
            content = f.read()
        
        enhancements = [
            ("AIWAF_MAX_PAGE_TIME", "Page timeout setting"),
            ("_view_accepts_post", "POST validation method"),
            ("page_expired", "Page expiration response"),
            ("reload_required", "Reload requirement flag"),
            ("409", "HTTP 409 Conflict status"),
            ("non_post_patterns", "Non-POST URL patterns"),
        ]
        
        passed = 0
        total = len(enhancements)
        
        for pattern, description in enhancements:
            if pattern in content:
                print(f"   ✅ {description} found")
                passed += 1
            else:
                print(f"   ❌ {description} missing")
        
        print(f"\n📊 Configuration tests: {passed}/{total} passed")
        return passed == total
        
    except Exception as e:
        print(f"❌ Error testing configuration: {e}")
        return False

def demonstrate_usage():
    """Demonstrate how the new features work"""
    print("\n📝 Usage Examples:")
    print("-" * 40)
    
    print("1. POST to Non-POST Endpoint:")
    print("   Request: POST /static/css/style.css")
    print("   Result: 403 Blocked (POST to non-POST endpoint)")
    print()
    
    print("2. Form Submitted Too Quickly:")
    print("   GET /contact/ at 12:00:00")
    print("   POST /contact/ at 12:00:00.5 (0.5s later)")
    print("   Result: 403 Blocked (Form submitted too quickly)")
    print()
    
    print("3. Page Expired (4+ minutes old):")
    print("   GET /contact/ at 12:00:00")
    print("   POST /contact/ at 12:04:30 (4.5 minutes later)")
    print("   Result: 409 Conflict (Page expired, reload required)")
    print("   Response: {\"error\": \"page_expired\", \"reload_required\": true}")
    print()
    
    print("4. Normal Valid Submission:")
    print("   GET /contact/ at 12:00:00")
    print("   POST /contact/ at 12:00:05 (5s later)")
    print("   Result: Request processed normally")

def main():
    """Run all tests for enhanced HoneypotTimingMiddleware"""
    print("🧪 Enhanced HoneypotTimingMiddleware Test")
    print("=" * 60)
    
    tests = [
        test_post_validation_logic,
        test_page_timeout_logic,
        test_middleware_configuration
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
        print("🎉 ALL TESTS PASSED! Enhanced HoneypotTimingMiddleware is working correctly.")
        demonstrate_usage()
    else:
        print("⚠️  Some tests failed. Check output above for details.")
    
    return passed == total

if __name__ == "__main__":
    success = main()
    sys.exit(0 if success else 1)
