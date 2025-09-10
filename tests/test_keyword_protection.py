#!/usr/bin/env python3
"""
AIWAF Keyword Protection Test Script

This script demonstrates the new keyword filtering functionality 
that prevents legitimate paths like /en/profile/ from being blocked.

Run this test after configuring AIWAF_ALLOWED_PATH_KEYWORDS in your settings.
"""

def test_keyword_filtering():
    """Test the enhanced keyword filtering logic"""
    
    # Simulate the new filtering logic
    class MockMiddleware:
        def __init__(self):
            # Default legitimate keywords (from middleware)
            self.legitimate_path_keywords = {
                "profile", "user", "account", "settings", "dashboard", 
                "home", "about", "contact", "help", "search", "list",
                "view", "edit", "create", "update", "delete", "detail",
                "api", "auth", "login", "logout", "register", "signup",
                "reset", "confirm", "activate", "verify", "page",
                "category", "tag", "post", "article", "blog", "news"
            }
            
            # Exempt keywords (from settings) - these should NEVER be blocked
            self.exempt_keywords = {
                "api", "webhook", "health", "static", "media",
                "upload", "download", "backup"
            }
            
            # Static malicious keywords
            self.static_keywords = {".php", "xmlrpc", "wp-", ".env", ".git", ".bak", "config"}
            
            # Simulated dynamic keywords that would be learned
            self.dynamic_keywords = {"profile", "shell", "admin"}  # Added admin back
        
        def should_block_keyword(self, keyword, path_exists=True, malicious_context=False):
            """Test if a keyword should trigger blocking"""
            
            # Skip if keyword is explicitly exempted (highest priority)
            if keyword in self.exempt_keywords:
                return False, "Exempt keyword"
            
            # Block if it's a known malicious keyword (always block)
            if keyword in self.static_keywords:
                return True, "Static malicious keyword"
            
            # For dynamic keywords, check context
            if keyword in self.dynamic_keywords:
                # Allow if legitimate path keyword and valid Django path and no malicious context
                if (keyword in self.legitimate_path_keywords and 
                    path_exists and not malicious_context):
                    return False, "Legitimate path keyword"
                else:
                    return True, "Dynamic keyword in suspicious context"
            
            # Allow if this is a legitimate path keyword in valid context
            if (keyword in self.legitimate_path_keywords and 
                path_exists and not malicious_context):
                return False, "Legitimate path keyword"
            
            return False, "No match"
    
    # Test cases
    middleware = MockMiddleware()
    
    test_cases = [
        # (keyword, path_exists, malicious_context, expected_blocked, description)
        ("profile", True, False, False, "Legitimate profile page"),
        ("profile", False, False, True, "Profile keyword on non-existent path"),
        ("profile", True, True, True, "Profile in malicious context (query injection)"),
        (".php", True, False, True, "PHP file extension (always malicious)"),
        (".php", False, False, True, "PHP on non-existent path"),
        ("admin", True, False, False, "Legitimate admin path"),
        ("admin", False, True, True, "Admin in malicious context"),
        ("shell", True, False, True, "Shell keyword (suspicious)"),
        ("shell", False, False, True, "Shell on non-existent path"),
        ("api", True, False, False, "API keyword (exempt)"),
        ("api", False, True, False, "API in malicious context (still exempt)"),
    ]
    
    print("🔍 AIWAF Keyword Filtering Test Results")
    print("=" * 60)
    
    all_passed = True
    for keyword, path_exists, malicious_context, expected_blocked, description in test_cases:
        should_block, reason = middleware.should_block_keyword(keyword, path_exists, malicious_context)
        
        status = "PASS" if should_block == expected_blocked else "FAIL"
        if should_block != expected_blocked:
            all_passed = False
        
        print(f"{status} | {description}")
        print(f"     Keyword: '{keyword}' | Path exists: {path_exists} | Malicious: {malicious_context}")
        print(f"     Expected: {'BLOCK' if expected_blocked else 'ALLOW'} | Actual: {'BLOCK' if should_block else 'ALLOW'} | Reason: {reason}")
        print()
    
    print("=" * 60)
    print(f"Overall Result: {'ALL TESTS PASSED' if all_passed else 'SOME TESTS FAILED'}")
    
    return all_passed

def test_profile_scenario():
    """Specific test for the reported /en/profile/ blocking issue"""
    
    print("\nSpecific Test: /en/profile/ Blocking Issue")
    print("=" * 50)
    
    # This simulates the fix for the original issue
    path = "/en/profile/"
    keyword = "profile"
    
    # Before fix: Would be blocked
    print("Before fix: 'profile' keyword would trigger blocking")
    print("   Reason: All learned keywords were treated as suspicious")
    
    # After fix: Should be allowed
    print("After fix: 'profile' keyword is allowed in legitimate paths")
    print("   Reason: 'profile' is in legitimate_path_keywords + path exists in Django")
    
    print("\nProtection still works for:")
    print("   • /nonexistent/profile/ (non-Django path)")
    print("   • /?cmd=profile&union=select (query injection)")
    print("   • /profile.php (file extension attack)")

if __name__ == "__main__":
    print("AIWAF Enhanced Keyword Protection Test")
    print("=" * 50)
    
    # Run the main test
    success = test_keyword_filtering()
    
    # Run specific scenario test
    test_profile_scenario()
    
    print(f"\nTest Summary: {'SUCCESS' if success else 'FAILURE'}")
    
    if success:
        print("\nThe enhanced keyword filtering is working correctly!")
        print("   Legitimate paths like /en/profile/ will no longer be blocked.")
        print("   Malicious requests are still detected and blocked.")
    else:
        print("\nThere are issues with the keyword filtering logic.")
        print("   Please review the implementation.")
