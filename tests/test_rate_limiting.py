#!/usr/bin/env python3
"""
Test script to verify AIWAF rate limiting works correctly.
This script simulates burst requests to test the RateLimitMiddleware.
"""

import time
import requests
import sys
from concurrent.futures import ThreadPoolExecutor, as_completed

def test_rate_limiting(base_url="http://localhost:8000", test_path="/test-burst"):
    """
    Test rate limiting by sending burst requests
    """
    print(f"🧪 Testing Rate Limiting on {base_url}{test_path}")
    print("=" * 60)
    
    # Test configuration
    burst_count = 50  # Number of requests to send
    concurrent_threads = 10  # Number of concurrent requests
    
    print(f"📊 Test Parameters:")
    print(f"   - Total requests: {burst_count}")
    print(f"   - Concurrent threads: {concurrent_threads}")
    print(f"   - Target URL: {base_url}{test_path}")
    print()
    
    # Track responses
    responses = {
        200: 0,  # OK
        403: 0,  # Blocked
        404: 0,  # Not Found (expected)
        429: 0,  # Too Many Requests
        'errors': 0  # Connection errors
    }
    
    def make_request(request_num):
        """Make a single request and return the response status"""
        try:
            response = requests.get(f"{base_url}{test_path}", timeout=5)
            return request_num, response.status_code, time.time()
        except requests.exceptions.RequestException as e:
            return request_num, 'error', time.time()
    
    start_time = time.time()
    
    # Send burst requests
    print("🚀 Sending burst requests...")
    with ThreadPoolExecutor(max_workers=concurrent_threads) as executor:
        # Submit all requests
        futures = [executor.submit(make_request, i) for i in range(burst_count)]
        
        # Collect results
        for future in as_completed(futures):
            request_num, status_code, timestamp = future.result()
            
            if status_code == 'error':
                responses['errors'] += 1
            elif status_code in responses:
                responses[status_code] += 1
            else:
                print(f"   Unexpected status code: {status_code}")
    
    end_time = time.time()
    duration = end_time - start_time
    
    # Analyze results
    print(f"\n📈 Results after {duration:.2f} seconds:")
    print("-" * 40)
    for status, count in responses.items():
        if count > 0:
            percentage = (count / burst_count) * 100
            if status == 429:
                print(f"   {status} (Too Many Requests): {count} ({percentage:.1f}%) ✅")
            elif status == 403:
                print(f"   {status} (Blocked): {count} ({percentage:.1f}%) ✅")
            elif status == 404:
                print(f"   {status} (Not Found): {count} ({percentage:.1f}%) ✅")
            elif status == 200:
                print(f"   {status} (OK): {count} ({percentage:.1f}%)")
            else:
                print(f"   {status}: {count} ({percentage:.1f}%)")
    
    # Interpretation
    print(f"\n🔍 Analysis:")
    
    if responses[429] > 0:
        print("   ✅ Rate limiting is working (429 responses received)")
    else:
        print("   ❌ No rate limiting detected (no 429 responses)")
    
    if responses[403] > 0:
        print("   ✅ IP blocking is working (403 responses received)")
    else:
        print("   ⚠️  No IP blocking detected (no 403 responses)")
    
    if responses['errors'] > 0:
        print(f"   ⚠️  {responses['errors']} connection errors (server may be overwhelmed)")
    
    # Rate calculation
    successful_requests = sum(responses.values()) - responses['errors']
    rps = successful_requests / duration if duration > 0 else 0
    print(f"   📊 Request rate: {rps:.1f} requests/second")
    
    # Recommendations
    print(f"\n💡 Recommendations:")
    
    if responses[429] == 0 and responses[403] == 0:
        print("   🚨 ISSUE: No rate limiting detected!")
        print("   - Check that RateLimitMiddleware is in MIDDLEWARE setting")
        print("   - Verify Django cache is configured")
        print("   - Check if your IP is exempted")
        print("   - Default limits: 20 requests/10s (soft), 40 requests/10s (hard)")
        return False
    
    elif responses[429] > 0 and responses[403] == 0:
        print("   ✅ Soft rate limiting working (429 responses)")
        print("   ⚠️  Hard rate limiting not triggered (no IP blocking)")
        print("   - This is normal if burst was under AIWAF_RATE_FLOOD limit")
        return True
    
    elif responses[403] > 0:
        print("   ✅ Hard rate limiting working (IP blocking active)")
        print("   - IP may now be temporarily blocked")
        print("   - Use 'python manage.py aiwaf_reset --blacklist' to unblock")
        return True
    
    else:
        print("   ✅ Rate limiting appears to be working correctly")
        return True

def main():
    """Main test function"""
    if len(sys.argv) > 1:
        base_url = sys.argv[1]
    else:
        base_url = "http://localhost:8000"
    
    print("🧪 AIWAF Rate Limiting Test")
    print("=" * 60)
    print("This script tests if AIWAF rate limiting is working by sending burst requests.")
    print("Make sure your Django server is running first!")
    print()
    
    try:
        # Test basic connectivity first
        print("🔗 Testing connectivity...")
        response = requests.get(base_url, timeout=5)
        print(f"   ✅ Server responding (status: {response.status_code})")
    except requests.exceptions.RequestException as e:
        print(f"   ❌ Cannot connect to server: {e}")
        print(f"   Make sure Django is running on {base_url}")
        return False
    
    print()
    
    # Run the rate limiting test
    success = test_rate_limiting(base_url)
    
    print("\n" + "=" * 60)
    if success:
        print("🎉 Rate limiting test completed successfully!")
    else:
        print("❌ Rate limiting test failed - check configuration!")
    
    return success

if __name__ == "__main__":
    success = main()
    sys.exit(0 if success else 1)
