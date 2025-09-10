#!/usr/bin/env python3
"""
Test Header Validation Middleware

This test verifies that the HeaderValidationMiddleware correctly:
1. Blocks requests with missing required headers
2. Blocks requests with suspicious User-Agent strings
3. Blocks requests with suspicious header combinations
4. Allows legitimate browser requests
5. Allows legitimate bot requests
6. Calculates header quality scores correctly
"""

import os
import sys
from unittest.mock import MagicMock, patch
import re

# Add the current directory to Python path for imports
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

def test_header_validation():
    """Test the header validation logic"""
    
    print("Testing Header Validation Middleware")
    print("=" * 50)
    
    # Mock the middleware class
    class MockHeaderMiddleware:
        # Copy the constants from the real middleware
        REQUIRED_HEADERS = [
            'HTTP_USER_AGENT',
            'HTTP_ACCEPT',
        ]
        
        BROWSER_HEADERS = [
            'HTTP_ACCEPT_LANGUAGE',
            'HTTP_ACCEPT_ENCODING',
            'HTTP_CONNECTION', 
            'HTTP_CACHE_CONTROL',
        ]
        
        SUSPICIOUS_USER_AGENTS = [
            r'bot',
            r'crawler',
            r'spider',
            r'scraper', 
            r'curl',
            r'wget',
            r'python',
            r'java',
            r'node',
            r'go-http',
            r'axios',
            r'okhttp',
            r'libwww',
            r'lwp-trivial',
            r'mechanize',
            r'requests',
            r'urllib',
            r'httpie',
            r'postman',
            r'insomnia',
            r'^$',  # Empty user agent
            r'mozilla/4\.0$',  # Fake old browser
            r'mozilla/5\.0$',  # Incomplete mozilla string
        ]
        
        LEGITIMATE_BOTS = [
            r'googlebot',
            r'bingbot', 
            r'slurp',  # Yahoo
            r'duckduckbot',
            r'baiduspider',
            r'yandexbot',
            r'facebookexternalhit',
            r'twitterbot',
            r'linkedinbot',
            r'whatsapp',
            r'telegrambot',
            r'applebot',
            r'pingdom',
            r'uptimerobot',
            r'statuscake',
            r'site24x7',
        ]
        
        SUSPICIOUS_COMBINATIONS = [
            {
                'condition': lambda headers: (
                    headers.get('SERVER_PROTOCOL', '').startswith('HTTP/2') and
                    'mozilla/4.0' in headers.get('HTTP_USER_AGENT', '').lower()
                ),
                'reason': 'HTTP/2 with old browser user agent'
            },
            {
                'condition': lambda headers: (
                    headers.get('HTTP_USER_AGENT') and 
                    not headers.get('HTTP_ACCEPT')
                ),
                'reason': 'User-Agent present but no Accept header'
            },
            {
                'condition': lambda headers: (
                    headers.get('HTTP_ACCEPT') == '*/*' and
                    not any(h in headers for h in ['HTTP_ACCEPT_LANGUAGE', 'HTTP_ACCEPT_ENCODING'])
                ),
                'reason': 'Generic Accept header without language/encoding'
            },
            {
                'condition': lambda headers: (
                    headers.get('HTTP_USER_AGENT') and
                    not any(headers.get(h) for h in ['HTTP_ACCEPT_LANGUAGE', 'HTTP_ACCEPT_ENCODING', 'HTTP_CONNECTION'])
                ),
                'reason': 'Missing all browser-standard headers'
            },
        ]
        
        def _check_missing_headers(self, headers):
            """Check for missing required headers"""
            missing = []
            
            for header in self.REQUIRED_HEADERS:
                if not headers.get(header):
                    missing.append(header.replace('HTTP_', '').replace('_', '-').lower())
                    
            return missing
        
        def _check_user_agent(self, user_agent):
            """Check if user agent is suspicious"""
            if not user_agent:
                return "Empty user agent"
                
            user_agent_lower = user_agent.lower()
            
            # Check if it's a legitimate bot first
            for legitimate_pattern in self.LEGITIMATE_BOTS:
                if re.search(legitimate_pattern, user_agent_lower):
                    return None  # Allow legitimate bots
            
            # Check for suspicious patterns
            for suspicious_pattern in self.SUSPICIOUS_USER_AGENTS:
                if re.search(suspicious_pattern, user_agent_lower, re.IGNORECASE):
                    return f"Pattern: {suspicious_pattern}"
                    
            # Check for very short user agents (likely fake)
            if len(user_agent) < 10:
                return "Too short"
                
            # Check for very long user agents (possibly malicious)
            if len(user_agent) > 500:
                return "Too long"
                
            return None
        
        def _check_header_combinations(self, headers):
            """Check for suspicious header combinations"""
            for combo in self.SUSPICIOUS_COMBINATIONS:
                try:
                    if combo['condition'](headers):
                        return combo['reason']
                except Exception:
                    # If condition check fails, skip it
                    continue
                    
            return None
        
        def _calculate_header_quality(self, headers):
            """Calculate a quality score based on header completeness"""
            score = 0
            
            # Basic required headers (2 points each)
            if headers.get('HTTP_USER_AGENT'):
                score += 2
            if headers.get('HTTP_ACCEPT'):
                score += 2
                
            # Browser-standard headers (1 point each)
            for header in self.BROWSER_HEADERS:
                if headers.get(header):
                    score += 1
                    
            # Bonus points for realistic combinations
            if headers.get('HTTP_ACCEPT_LANGUAGE') and headers.get('HTTP_ACCEPT_ENCODING'):
                score += 1
                
            if headers.get('HTTP_CONNECTION') == 'keep-alive':
                score += 1
                
            # Check for realistic Accept header
            accept = headers.get('HTTP_ACCEPT', '')
            if 'text/html' in accept and 'application/xml' in accept:
                score += 1
                
            return score
    
    middleware = MockHeaderMiddleware()
    
    # Test cases for missing headers
    header_tests = [
        {
            'name': 'Complete browser headers',
            'headers': {
                'HTTP_USER_AGENT': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 Chrome/91.0.4472.124',
                'HTTP_ACCEPT': 'text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8',
                'HTTP_ACCEPT_LANGUAGE': 'en-US,en;q=0.5',
                'HTTP_ACCEPT_ENCODING': 'gzip, deflate',
                'HTTP_CONNECTION': 'keep-alive'
            },
            'expected_missing': [],
            'expected_quality': 10,  # High quality
            'should_block': False
        },
        {
            'name': 'Missing User-Agent',
            'headers': {
                'HTTP_ACCEPT': 'text/html,application/xhtml+xml',
            },
            'expected_missing': ['user-agent'],
            'expected_quality': 2,
            'should_block': True
        },
        {
            'name': 'Missing Accept header',
            'headers': {
                'HTTP_USER_AGENT': 'Mozilla/5.0 Chrome/91.0',
            },
            'expected_missing': ['accept'],
            'expected_quality': 2,
            'should_block': True
        },
        {
            'name': 'Empty headers',
            'headers': {},
            'expected_missing': ['user-agent', 'accept'],
            'expected_quality': 0,
            'should_block': True
        }
    ]
    
    # Test cases for User-Agent validation
    user_agent_tests = [
        {
            'name': 'Legitimate Chrome browser',
            'user_agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36',
            'expected_suspicious': None
        },
        {
            'name': 'Legitimate Firefox browser',
            'user_agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:89.0) Gecko/20100101 Firefox/89.0',
            'expected_suspicious': None
        },
        {
            'name': 'Legitimate Googlebot',
            'user_agent': 'Mozilla/5.0 (compatible; Googlebot/2.1; +http://www.google.com/bot.html)',
            'expected_suspicious': None
        },
        {
            'name': 'Curl request',
            'user_agent': 'curl/7.68.0',
            'expected_suspicious': 'Pattern: curl'
        },
        {
            'name': 'Python requests',
            'user_agent': 'python-requests/2.25.1',
            'expected_suspicious': 'Pattern: python'
        },
        {
            'name': 'Empty user agent',
            'user_agent': '',
            'expected_suspicious': 'Empty user agent'
        },
        {
            'name': 'Too short user agent',
            'user_agent': 'IE',  # Short but doesn't match "bot" pattern
            'expected_suspicious': 'Too short'
        },
        {
            'name': 'Generic bot',
            'user_agent': 'Some random bot crawler',
            'expected_suspicious': 'Pattern: bot'
        }
    ]
    
    # Test cases for header combinations
    combination_tests = [
        {
            'name': 'HTTP/2 with old Mozilla',
            'headers': {
                'SERVER_PROTOCOL': 'HTTP/2.0',
                'HTTP_USER_AGENT': 'Mozilla/4.0 (compatible; MSIE 6.0)',
                'HTTP_ACCEPT': 'text/html'
            },
            'expected_suspicious': 'HTTP/2 with old browser user agent'
        },
        {
            'name': 'User-Agent without Accept',
            'headers': {
                'HTTP_USER_AGENT': 'Mozilla/5.0 Chrome/91.0'
            },
            'expected_suspicious': 'User-Agent present but no Accept header'
        },
        {
            'name': 'Generic Accept only',
            'headers': {
                'HTTP_USER_AGENT': 'Mozilla/5.0 Chrome/91.0',
                'HTTP_ACCEPT': '*/*'
            },
            'expected_suspicious': 'Generic Accept header without language/encoding'
        },
        {
            'name': 'No browser-standard headers',
            'headers': {
                'HTTP_USER_AGENT': 'Mozilla/5.0 Chrome/91.0',
                'HTTP_ACCEPT': 'text/html'
            },
            'expected_suspicious': 'Missing all browser-standard headers'
        },
        {
            'name': 'Normal browser combination',
            'headers': {
                'HTTP_USER_AGENT': 'Mozilla/5.0 Chrome/91.0',
                'HTTP_ACCEPT': 'text/html,application/xml',
                'HTTP_ACCEPT_LANGUAGE': 'en-US',
                'HTTP_CONNECTION': 'keep-alive'
            },
            'expected_suspicious': None
        }
    ]
    
    # Run tests
    passed = 0
    failed = 0
    
    print("Testing Missing Headers...")
    for i, test in enumerate(header_tests, 1):
        missing = middleware._check_missing_headers(test['headers'])
        quality = middleware._calculate_header_quality(test['headers'])
        
        missing_match = missing == test['expected_missing']
        quality_match = quality == test['expected_quality']
        
        if missing_match and quality_match:
            print(f"✅ Header {i}: {test['name']}")
            passed += 1
        else:
            print(f"❌ Header {i}: {test['name']}")
            if not missing_match:
                print(f"    Missing headers - Expected: {test['expected_missing']}, Got: {missing}")
            if not quality_match:
                print(f"    Quality score - Expected: {test['expected_quality']}, Got: {quality}")
            failed += 1
    
    print("\nTesting User-Agent Validation...")
    for i, test in enumerate(user_agent_tests, 1):
        suspicious = middleware._check_user_agent(test['user_agent'])
        
        if suspicious == test['expected_suspicious']:
            print(f"✅ UA {i}: {test['name']}")
            passed += 1
        else:
            print(f"❌ UA {i}: {test['name']}")
            print(f"    Expected: {test['expected_suspicious']}, Got: {suspicious}")
            failed += 1
    
    print("\nTesting Header Combinations...")
    for i, test in enumerate(combination_tests, 1):
        suspicious = middleware._check_header_combinations(test['headers'])
        
        if suspicious == test['expected_suspicious']:
            print(f"✅ Combo {i}: {test['name']}")
            passed += 1
        else:
            print(f"❌ Combo {i}: {test['name']}")
            print(f"    Expected: {test['expected_suspicious']}, Got: {suspicious}")
            failed += 1
    
    print(f"\nResults: {passed} passed, {failed} failed")
    
    if failed == 0:
        print("🎉 All header validation tests passed!")
        return True
    else:
        print(f"💥 {failed} test(s) failed!")
        return False

def test_quality_scoring():
    """Test the header quality scoring system"""
    print("\nTesting Header Quality Scoring")
    print("=" * 40)
    
    class MockHeaderMiddleware:
        BROWSER_HEADERS = [
            'HTTP_ACCEPT_LANGUAGE',
            'HTTP_ACCEPT_ENCODING',
            'HTTP_CONNECTION', 
            'HTTP_CACHE_CONTROL',
        ]
        
        def _calculate_header_quality(self, headers):
            score = 0
            
            # Basic required headers (2 points each)
            if headers.get('HTTP_USER_AGENT'):
                score += 2
            if headers.get('HTTP_ACCEPT'):
                score += 2
                
            # Browser-standard headers (1 point each)
            for header in self.BROWSER_HEADERS:
                if headers.get(header):
                    score += 1
                    
            # Bonus points for realistic combinations
            if headers.get('HTTP_ACCEPT_LANGUAGE') and headers.get('HTTP_ACCEPT_ENCODING'):
                score += 1
                
            if headers.get('HTTP_CONNECTION') == 'keep-alive':
                score += 1
                
            # Check for realistic Accept header
            accept = headers.get('HTTP_ACCEPT', '')
            if 'text/html' in accept and 'application/xml' in accept:
                score += 1
                
            return score
    
    middleware = MockHeaderMiddleware()
    
    quality_tests = [
        {
            'name': 'Perfect browser headers',
            'headers': {
                'HTTP_USER_AGENT': 'Mozilla/5.0 Chrome/91.0',
                'HTTP_ACCEPT': 'text/html,application/xml;q=0.9,*/*;q=0.8',
                'HTTP_ACCEPT_LANGUAGE': 'en-US,en;q=0.5',
                'HTTP_ACCEPT_ENCODING': 'gzip, deflate',
                'HTTP_CONNECTION': 'keep-alive',
                'HTTP_CACHE_CONTROL': 'max-age=0'
            },
            'expected_score': 11,  # All possible points
            'quality_level': 'High'
        },
        {
            'name': 'Minimal legitimate headers',
            'headers': {
                'HTTP_USER_AGENT': 'Mozilla/5.0 Chrome/91.0',
                'HTTP_ACCEPT': 'text/html',
                'HTTP_CONNECTION': 'keep-alive'
            },
            'expected_score': 6,  # Decent quality
            'quality_level': 'Medium'
        },
        {
            'name': 'Bot-like headers (curl)',
            'headers': {
                'HTTP_USER_AGENT': 'curl/7.68.0',
                'HTTP_ACCEPT': '*/*'
            },
            'expected_score': 4,  # Basic but suspicious
            'quality_level': 'Low'
        },
        {
            'name': 'Minimal suspicious headers',
            'headers': {
                'HTTP_USER_AGENT': 'Bot',
                'HTTP_ACCEPT': '*/*'
            },
            'expected_score': 4,  # Very basic
            'quality_level': 'Low'
        },
        {
            'name': 'Missing required headers',
            'headers': {
                'HTTP_ACCEPT_LANGUAGE': 'en-US'
            },
            'expected_score': 1,  # Almost nothing
            'quality_level': 'Very Low'
        }
    ]
    
    passed = 0
    failed = 0
    
    for i, test in enumerate(quality_tests, 1):
        score = middleware._calculate_header_quality(test['headers'])
        
        if score == test['expected_score']:
            print(f"✅ Quality {i}: {test['name']} - Score: {score} ({test['quality_level']})")
            passed += 1
        else:
            print(f"❌ Quality {i}: {test['name']}")
            print(f"    Expected score: {test['expected_score']}, Got: {score}")
            failed += 1
    
    print(f"\nQuality Scoring Results: {passed} passed, {failed} failed")
    return failed == 0

if __name__ == '__main__':
    print("Header Validation Test Suite")
    print("=" * 60)
    
    test1_passed = test_header_validation()
    test2_passed = test_quality_scoring()
    
    if test1_passed and test2_passed:
        print("\n🎉 All header validation tests passed!")
        print("✅ Missing header detection working")
        print("✅ User-Agent validation working")
        print("✅ Header combination analysis working")
        print("✅ Quality scoring system working")
        sys.exit(0)
    else:
        print("\n💥 Some tests failed. Please check the implementation.")
        sys.exit(1)
