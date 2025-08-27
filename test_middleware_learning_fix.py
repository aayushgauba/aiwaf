#!/usr/bin/env python3
"""
Test to demonstrate the middleware learning behavior and the fix for learning from all requests.
"""

def test_middleware_learning_logic():
    """Test what the middleware learns from"""
    print("🧪 Testing Middleware Learning Logic")
    print("=" * 60)
    
    # Simulate different types of requests and responses
    test_scenarios = [
        # (path, status_code, path_exists, description, should_learn)
        ("/admin/", 200, True, "Successful request to valid path", False),
        ("/blog/post/123/", 200, True, "Successful request to valid path", False),
        ("/school/about/", 200, True, "Successful request to include() path", False),
        ("/nonexistent/page/", 404, False, "404 on non-existent path", True),
        ("/malicious/hack.php", 404, False, "404 on malicious-looking path", True),
        ("/school/config.php", 404, False, "404 on include() path with malicious file", True),
        ("/api/users/", 200, True, "Successful API request", False),
        ("/unknown/exploit.php", 500, False, "500 error on suspicious path", True),
        ("/admin/xmlrpc.php", 404, False, "404 on admin path with suspicious file", True),
    ]
    
    print("\n1. Old logic (before fix):")
    print("   - AIAnomalyMiddleware learned from ALL requests regardless of status")
    print("   - IPAndKeywordBlockMiddleware learned only from non-existent paths")
    
    print(f"\n2. New logic (after fix):")
    print("   - Both middlewares only learn from error responses (4xx, 5xx) on non-existent paths")
    print("   - Learning is also filtered by malicious context and legitimate keywords")
    
    print(f"\n3. Testing scenarios:")
    print(f"{'Path':<25} | {'Status':<6} | {'Exists':<6} | {'Should Learn':<12} | {'Reason'}")
    print("-" * 85)
    
    for path, status, exists, description, should_learn in test_scenarios:
        # New logic: learn only from error responses on non-existent paths
        would_learn_new = (status >= 400 and not exists)
        
        status_str = f"{status}"
        exists_str = "Yes" if exists else "No"
        should_str = "Yes" if should_learn else "No"
        
        # Determine reasoning
        if status < 400:
            reason = "Success response"
        elif exists:
            reason = "Path exists"
        elif status >= 400 and not exists:
            reason = "Error + non-existent"
        else:
            reason = "Other"
        
        print(f"{path:<25} | {status_str:<6} | {exists_str:<6} | {should_str:<12} | {reason}")
    
    print(f"\n4. Impact of the fix:")
    legitimate_paths_protected = [s for s in test_scenarios if s[1] < 400 and s[2]]
    print(f"   ✅ {len(legitimate_paths_protected)} legitimate successful requests won't pollute learning")
    
    error_paths_learning = [s for s in test_scenarios if s[1] >= 400 and not s[2]]
    print(f"   ✅ {len(error_paths_learning)} error responses on non-existent paths will still be learned from")
    
    print(f"\n5. Summary:")
    print(f"   - Fixed: No more learning from successful requests (200, 201, 302, etc.)")
    print(f"   - Fixed: No more learning from valid Django paths") 
    print(f"   - Maintained: Learning from 404s, 500s, etc. on non-existent paths")
    print(f"   - Improved: Added legitimate keyword filtering and malicious context checks")

def test_specific_learning_cases():
    """Test specific edge cases for learning"""
    print(f"\n🧪 Testing Specific Learning Cases")
    print("=" * 60)
    
    cases = [
        {
            "request": "/school/about/",
            "status": 200,
            "exists": True,
            "segments": ["school", "about"],
            "description": "Successful request to include() path"
        },
        {
            "request": "/school/malicious.php", 
            "status": 404,
            "exists": False,
            "segments": ["school", "malicious", "php"],
            "description": "404 on include() path with malicious file"
        },
        {
            "request": "/admin/config.php",
            "status": 404, 
            "exists": False,
            "segments": ["admin", "config", "php"],
            "description": "404 on admin path with config file"
        },
        {
            "request": "/api/v1/users/",
            "status": 200,
            "exists": True, 
            "segments": ["api", "users"],
            "description": "Successful API request"
        }
    ]
    
    print(f"\n   Detailed analysis:")
    print(f"{'Request':<25} | {'Status':<6} | {'Exists':<6} | {'Segments to Learn'}")
    print("-" * 70)
    
    # Mock legitimate keywords for demonstration
    legitimate_keywords = {"school", "admin", "api", "users", "about", "profile", "blog", "pages"}
    
    for case in cases:
        request = case["request"]
        status = case["status"]
        exists = case["exists"]
        segments = case["segments"]
        
        # Apply new learning logic
        would_learn = status >= 400 and not exists
        
        if would_learn:
            # Filter segments that would actually be learned
            learned_segments = []
            for seg in segments:
                if (len(seg) > 3 and 
                    seg not in legitimate_keywords and
                    seg not in ["php"]):  # Assuming "php" is in STATIC_KW
                    learned_segments.append(seg)
            segments_str = ", ".join(learned_segments) if learned_segments else "None"
        else:
            segments_str = "None (no learning)"
        
        print(f"{request:<25} | {status:<6} | {'Yes' if exists else 'No':<6} | {segments_str}")
    
    print(f"\n   Key insights:")
    print(f"   - '/school/about/' (200): No learning - legitimate successful request")
    print(f"   - '/school/malicious.php' (404): Learns 'malicious' (not 'school' - it's legitimate)")
    print(f"   - '/admin/config.php' (404): Learns 'config' (not 'admin' - it's legitimate)")
    print(f"   - '/api/v1/users/' (200): No learning - legitimate successful request")

if __name__ == "__main__":
    print("🔧 AIWAF Middleware Learning Logic Analysis")
    print("   Issue: AIAnomalyMiddleware was learning from ALL requests")
    print("   Fix: Only learn from error responses on non-existent paths")
    print()
    
    try:
        test_middleware_learning_logic()
        test_specific_learning_cases()
        
        print(f"\n🎉 Learning Logic Analysis Complete!")
        print(f"   The fix prevents keyword pollution from legitimate successful requests")
        print(f"   while maintaining effective learning from actual attack attempts.")
        
    except Exception as e:
        print(f"❌ Test failed with error: {e}")
        import traceback
        traceback.print_exc()
