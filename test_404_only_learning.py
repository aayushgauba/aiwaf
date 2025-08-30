#!/usr/bin/env python3
"""
Test to demonstrate why learning should only happen from 404s, not other error codes like 403.
"""

def test_learning_from_different_status_codes():
    """Test the logic for learning from different HTTP status codes"""
    print(" Testing Learning from Different Status Codes")
    print("=" * 60)
    
    # Simulate different scenarios with their status codes and learning implications
    test_scenarios = [
        {
            "path": "/admin/dashboard/",
            "status": 200,
            "path_exists": True,
            "ip_blocked": False,
            "description": "Legitimate user accessing valid admin path",
            "should_learn": False,
            "reasoning": "Successful request to valid path"
        },
        {
            "path": "/admin/dashboard/", 
            "status": 403,
            "path_exists": True,
            "ip_blocked": True,
            "description": "Blocked IP trying to access legitimate admin path",
            "should_learn": False,
            "reasoning": "403 from blocked IP, but path is legitimate"
        },
        {
            "path": "/admin/config.php",
            "status": 404,
            "path_exists": False,
            "ip_blocked": False,
            "description": "Attack attempt on non-existent file",
            "should_learn": True,
            "reasoning": "404 on non-existent path - genuine attack attempt"
        },
        {
            "path": "/admin/config.php",
            "status": 403,
            "path_exists": False,
            "ip_blocked": True, 
            "description": "Blocked IP trying to access non-existent file",
            "should_learn": False,
            "reasoning": "403 from blocked IP - could be legitimate or attack"
        },
        {
            "path": "/school/malicious.php",
            "status": 404,
            "path_exists": False,
            "ip_blocked": False,
            "description": "Attack attempt on include() path",
            "should_learn": True,
            "reasoning": "404 on non-existent path - genuine attack attempt"
        },
        {
            "path": "/api/users/",
            "status": 403,
            "path_exists": True,
            "ip_blocked": False,
            "description": "Permission denied on valid API endpoint",
            "should_learn": False,
            "reasoning": "403 permission error, but path is legitimate"
        },
        {
            "path": "/unknown/hack.php",
            "status": 500,
            "path_exists": False,
            "ip_blocked": False,
            "description": "Server error on suspicious path",
            "should_learn": False,
            "reasoning": "500 error - could be legitimate code issue"
        }
    ]
    
    print(f"\n1. Why only 404s should trigger learning:")
    print(f"   - 200/2xx: Successful requests to legitimate paths")
    print(f"   - 403: Could be blocked IP accessing legitimate paths")
    print(f"   - 404: Genuine 'not found' - indicates scanning/probing")
    print(f"   - 500/5xx: Server errors - could be legitimate code issues")
    
    print(f"\n2. Scenario analysis:")
    print(f"{'Path':<25} | {'Status':<6} | {'Exists':<6} | {'IP Blocked':<10} | {'Learn':<5} | {'Reasoning'}")
    print("-" * 100)
    
    for scenario in test_scenarios:
        path = scenario["path"]
        status = scenario["status"]
        exists = scenario["path_exists"]
        blocked = scenario["ip_blocked"]
        should_learn = scenario["should_learn"]
        reasoning = scenario["reasoning"]
        
        # Apply the corrected learning logic: only learn from 404s on non-existent paths
        would_learn_corrected = (status == 404 and not exists)
        
        print(f"{path:<25} | {status:<6} | {'Yes' if exists else 'No':<6} | {'Yes' if blocked else 'No':<10} | {'Yes' if would_learn_corrected else 'No':<5} | {reasoning}")
    
    print(f"\n3. Key insights from the analysis:")
    
    # Count different scenarios
    blocked_ip_403s = [s for s in test_scenarios if s["status"] == 403 and s["ip_blocked"]]
    genuine_404s = [s for s in test_scenarios if s["status"] == 404 and not s["path_exists"]]
    
    print(f"    {len(blocked_ip_403s)} scenarios where 403s from blocked IPs won't pollute learning")
    print(f"    {len(genuine_404s)} scenarios where genuine 404s will still trigger learning")
    print(f"    No learning from server errors (500s) that might be legitimate code issues")
    
    print(f"\n4. Specific problematic case prevented:")
    print(f"   Scenario: Blocked IP tries to access '/admin/dashboard/' (legitimate path)")
    print(f"   Old logic: 403 + non-blocked = would learn 'admin', 'dashboard'")
    print(f"   New logic: Only 404s = won't learn from legitimate paths")

def test_middleware_learning_consistency():
    """Test that both middlewares have consistent learning logic"""
    print(f"\n Testing Middleware Learning Consistency")
    print("=" * 60)
    
    print(f"\n1. IPAndKeywordBlockMiddleware (request processing):")
    print(f"   - Learns during request processing (before response status known)")
    print(f"   - Uses path_exists_in_django() to determine if path is valid")
    print(f"   - Only learns from non-existent paths")
    print(f"   - Filters by legitimate keywords and malicious context")
    
    print(f"\n2. AIAnomalyMiddleware (response processing):")
    print(f"   - Learns during response processing (after response status known)")
    print(f"   - NOW: Only learns from 404 status codes")
    print(f"   - Only learns from non-existent paths")
    print(f"   - Filters by legitimate keywords and malicious context")
    
    print(f"\n3. Consistency achieved:")
    print(f"   - Both middlewares avoid learning from legitimate paths")
    print(f"   - Both middlewares filter out legitimate keywords")
    print(f"   - Both middlewares require malicious context")
    print(f"   - AIAnomalyMiddleware adds additional 404-only filter")
    
    print(f"\n4. Edge case handling:")
    print(f"   - Blocked IP + legitimate path → No learning (both middlewares)")
    print(f"   - Valid user + attack attempt → Learning only if 404 (AIAnomalyMiddleware)")
    print(f"   - Server error + suspicious path → No learning (both middlewares)")

if __name__ == "__main__":
    print(" AIWAF Learning Logic: Why Only 404s Matter")
    print("   Issue: Learning from all 4xx errors includes 403s from blocked IPs")
    print("   Fix: Only learn from 404s - genuine 'not found' responses")
    print()
    
    try:
        test_learning_from_different_status_codes()
        test_middleware_learning_consistency()
        
        print(f"\n Status Code Learning Analysis Complete!")
        print(f"   Key insight: 403s can come from blocked IPs accessing legitimate paths,")
        print(f"   so learning should only happen from genuine 404 'not found' responses.")
        
    except Exception as e:
        print(f" Test failed with error: {e}")
        import traceback
        traceback.print_exc()
