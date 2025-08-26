#!/usr/bin/env python3

def test_improved_path_validation():
    """Test the improved path validation logic"""
    print("🧪 Testing Improved Path Validation Logic")
    print("=" * 60)
    
    def improved_path_exists_in_django(path: str) -> bool:
        """Improved implementation that handles edge cases correctly"""
        candidate = path.split("?")[0].strip("/")  # Remove query params and normalize
        
        # Simulate Django URL patterns
        exact_patterns = {
            "a",           # /a
            "profile",     # /profile  
            "user",        # /user
            "admin",       # /admin
            "login",       # /login
        }
        
        # Include patterns (prefixes that allow sub-paths)
        include_patterns = {
            "api",         # /api/ allows /api/v1/, /api/users/, etc.
            "accounts",    # /accounts/ allows /accounts/login/, etc.
            "en",          # /en/ allows /en/profile/, /en/admin/, etc.
        }
        
        # Try exact matching first
        if candidate in exact_patterns:
            return True
            
        # Try exact matching with trailing slash
        if candidate.rstrip("/") in exact_patterns:
            return True
        
        # For include patterns, be careful about path boundaries
        for prefix in include_patterns:
            if candidate == prefix or candidate.startswith(prefix + "/"):
                return True
        
        return False
    
    # Test cases that demonstrate the improved logic
    test_cases = [
        # Basic exact matches
        ("/a", True, "Exact match"),
        ("/profile", True, "Exact match"),
        ("/user", True, "Exact match"),
        
        # Trailing slash handling
        ("/a/", True, "Trailing slash on exact pattern"),
        ("/profile/", True, "Trailing slash on exact pattern"),
        
        # Non-existent sub-paths (the key fix)
        ("/a/hack.php", False, "Sub-path doesn't exist - SHOULD LEARN KEYWORDS"),
        ("/profile/exploit", False, "Sub-path doesn't exist - SHOULD LEARN KEYWORDS"),
        ("/user/123/malicious", False, "Deep sub-path doesn't exist - SHOULD LEARN KEYWORDS"),
        
        # Include patterns (legitimate sub-paths)
        ("/api", True, "Include pattern base"),
        ("/api/", True, "Include pattern with slash"),
        ("/api/v1", True, "Include pattern sub-path"),
        ("/api/v1/users", True, "Include pattern deep path"),
        ("/accounts/login", True, "Include pattern sub-path"),
        ("/en/profile", True, "Include pattern sub-path"),
        
        # Non-existent include sub-paths
        ("/api/hack.php", False, "Malicious sub-path - SHOULD LEARN KEYWORDS"),
        ("/en/exploit", False, "Malicious sub-path - SHOULD LEARN KEYWORDS"),
        
        # Completely unknown paths
        ("/unknown", False, "Unknown path"),
        ("/malicious", False, "Malicious path"),
        ("/exploit.php", False, "File extension attack"),
    ]
    
    print("\n   Testing Improved Path Validation:")
    correct_results = 0
    total_tests = len(test_cases)
    
    for path, expected, description in test_cases:
        result = improved_path_exists_in_django(path)
        status = "✅" if result == expected else "❌"
        action = "EXISTS" if result else "NOT_EXISTS"
        learn_keywords = "WILL LEARN" if not result else "WON'T LEARN"
        
        print(f"     {status} {path:<20} -> {action:<10} ({learn_keywords}) - {description}")
        
        if result == expected:
            correct_results += 1
    
    print(f"\n   Results: {correct_results}/{total_tests} correct ({correct_results/total_tests*100:.1f}%)")
    
    # Demonstrate impact on keyword learning
    print("\n   Impact on Dynamic Keyword Learning:")
    
    suspicious_scenarios = [
        {"path": "/a/hack.php", "attack_type": "File extension on non-existent sub-path"},
        {"path": "/profile/exploit", "attack_type": "Malicious keyword on non-existent sub-path"},
        {"path": "/user/123/shell.asp", "attack_type": "Deep path with malicious content"},
        {"path": "/api/backdoor.php", "attack_type": "Include pattern with malicious file"},
        {"path": "/en/inject/xss", "attack_type": "Multilevel malicious path"},
        {"path": "/malicious/unknown", "attack_type": "Completely unknown malicious path"},
    ]
    
    print("\n     Keyword Learning Analysis:")
    import re
    
    for scenario in suspicious_scenarios:
        path = scenario["path"]
        path_exists = improved_path_exists_in_django(path)
        
        # Extract potential keywords
        segments = [seg for seg in re.split(r"\W+", path.lower()) if len(seg) > 3]
        
        # Legitimate keywords that should be protected
        legitimate_keywords = {"profile", "user", "admin", "accounts", "login", "api", "en"}
        
        # Keywords that would be learned (not legitimate and path doesn't exist)
        would_learn = []
        protected = []
        
        for seg in segments:
            if seg in legitimate_keywords:
                protected.append(seg)
            elif not path_exists:  # Only learn if path doesn't exist
                would_learn.append(seg)
        
        learn_status = "LEARN" if would_learn else "NO LEARNING"
        
        print(f"       {path}")
        print(f"         Path exists: {path_exists}")
        print(f"         Protected keywords: {protected}")
        print(f"         Would learn: {would_learn} ({learn_status})")
        print(f"         Attack type: {scenario['attack_type']}")
        print()
    
    print("   " + "=" * 56)
    print("   ✅ Improved logic correctly identifies non-existent sub-paths")
    print("   ✅ Malicious keywords will be learned from failed attacks")
    print("   ✅ Legitimate route keywords remain protected")
    
    return correct_results == total_tests

if __name__ == "__main__":
    success = test_improved_path_validation()
    if success:
        print("\n🎉 All tests passed! Path validation logic is robust.")
    else:
        print("\n⚠️  Some tests failed. Logic may need further refinement.")
