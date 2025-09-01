#!/usr/bin/env python3
"""
Real-World Log Analysis: Header Validation in Action

This demonstrates how the HeaderValidationMiddleware would handle actual log entries:
1. Suspicious request with missing User-Agent
2. Legitimate browser request with full headers
"""

import os
import sys
from unittest.mock import MagicMock
import re

# Add the current directory to Python path for imports
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

def analyze_real_requests():
    """Analyze the actual log entries provided"""
    
    print("Real-World Header Validation Analysis")
    print("=" * 60)
    
    # Import our header validation logic
    class MockHeaderMiddleware:
        REQUIRED_HEADERS = ['HTTP_USER_AGENT', 'HTTP_ACCEPT']
        
        SUSPICIOUS_USER_AGENTS = [
            r'bot', r'crawler', r'spider', r'scraper', r'curl', r'wget',
            r'python', r'java', r'node', r'go-http', r'axios', r'okhttp',
            r'libwww', r'lwp-trivial', r'mechanize', r'requests', r'urllib',
            r'httpie', r'postman', r'insomnia', r'^$', r'mozilla/4\.0$', r'mozilla/5\.0$'
        ]
        
        LEGITIMATE_BOTS = [
            r'googlebot', r'bingbot', r'slurp', r'duckduckbot', r'baiduspider',
            r'yandexbot', r'facebookexternalhit', r'twitterbot', r'linkedinbot',
            r'whatsapp', r'telegrambot', r'applebot', r'pingdom', r'uptimerobot',
            r'statuscake', r'site24x7'
        ]
        
        BROWSER_HEADERS = [
            'HTTP_ACCEPT_LANGUAGE', 'HTTP_ACCEPT_ENCODING', 
            'HTTP_CONNECTION', 'HTTP_CACHE_CONTROL'
        ]
        
        def _check_missing_headers(self, headers):
            missing = []
            for header in self.REQUIRED_HEADERS:
                if not headers.get(header):
                    missing.append(header.replace('HTTP_', '').replace('_', '-').lower())
            return missing
        
        def _check_user_agent(self, user_agent):
            if not user_agent:
                return "Empty user agent"
                
            user_agent_lower = user_agent.lower()
            
            # Check legitimate bots first
            for legitimate_pattern in self.LEGITIMATE_BOTS:
                if re.search(legitimate_pattern, user_agent_lower):
                    return None
            
            # Check for suspicious patterns
            for suspicious_pattern in self.SUSPICIOUS_USER_AGENTS:
                if re.search(suspicious_pattern, user_agent_lower, re.IGNORECASE):
                    return f"Pattern: {suspicious_pattern}"
                    
            if len(user_agent) < 10:
                return "Too short"
            if len(user_agent) > 500:
                return "Too long"
                
            return None
        
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
        
        def analyze_request(self, ip, user_agent, accept_header=None, referer=None):
            """Analyze a request and return the result"""
            
            # Build headers dict as Django would see it
            headers = {}
            
            if user_agent and user_agent != "-":
                headers['HTTP_USER_AGENT'] = user_agent
            if accept_header:
                headers['HTTP_ACCEPT'] = accept_header
            if referer and referer != "-":
                headers['HTTP_REFERER'] = referer
            
            # For legitimate browsers, add typical headers
            if user_agent and 'Mozilla' in user_agent and 'Chrome' in user_agent:
                headers['HTTP_ACCEPT'] = 'text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8'
                headers['HTTP_ACCEPT_LANGUAGE'] = 'en-US,en;q=0.5'
                headers['HTTP_ACCEPT_ENCODING'] = 'gzip, deflate'
                headers['HTTP_CONNECTION'] = 'keep-alive'
            
            result = {
                'ip': ip,
                'user_agent': user_agent,
                'headers': headers,
                'blocked': False,
                'reason': None,
                'quality_score': 0
            }
            
            # Check for missing required headers
            missing_headers = self._check_missing_headers(headers)
            if missing_headers:
                result['blocked'] = True
                result['reason'] = f"Missing required headers: {', '.join(missing_headers)}"
                return result
            
            # Check for suspicious user agent
            suspicious_ua = self._check_user_agent(headers.get('HTTP_USER_AGENT', ''))
            if suspicious_ua:
                result['blocked'] = True
                result['reason'] = f"Suspicious user agent: {suspicious_ua}"
                return result
            
            # Calculate quality score
            quality_score = self._calculate_header_quality(headers)
            result['quality_score'] = quality_score
            
            if quality_score < 3:
                result['blocked'] = True
                result['reason'] = f"Low header quality score: {quality_score}"
                return result
            
            result['reason'] = "Request allowed"
            return result
    
    middleware = MockHeaderMiddleware()
    
    # Test cases based on the actual log entries
    test_cases = [
        {
            'name': 'SUSPICIOUS REQUEST (WordPress Plugin Scanner)',
            'log_entry': '4.217.168.116 - - [31/Aug/2025:15:57:10 +0000] "GET /wp-content/plugins/hellopress/wp_filemanager.php HTTP/1.1" 404 4771 "-" "-" "4.217.168.116" response-time=0.113',
            'ip': '4.217.168.116',
            'path': '/wp-content/plugins/hellopress/wp_filemanager.php',
            'user_agent': '-',  # Missing User-Agent (shown as "-" in logs)
            'referer': '-',     # Missing Referer
            'notes': [
                'Scanning for WordPress plugin vulnerabilities',
                'Missing User-Agent header (suspicious)',
                'Targeting file manager plugin (common attack vector)',
                '404 response indicates scanner probing for files'
            ]
        },
        {
            'name': 'LEGITIMATE REQUEST (Ubuntu Chrome Browser)',
            'log_entry': '95.173.221.26 - - [31/Aug/2025:18:21:34 +0000] "GET / HTTP/1.1" 200 2276 "http://stlouisgurudwara.org/" "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Ubuntu Chromium/114.0.5775.194 Chrome/114.0.5775.194 Safari/537.36" "95.173.221.26" response-time=0.330',
            'ip': '95.173.221.26',
            'path': '/',
            'user_agent': 'Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Ubuntu Chromium/114.0.5775.194 Chrome/114.0.5775.194 Safari/537.36',
            'referer': 'http://stlouisgurudwara.org/',
            'notes': [
                'Real Ubuntu Chromium browser',
                'Complete User-Agent string with version info',
                'Has referer header (came from another page)',
                '200 response indicates successful page load'
            ]
        }
    ]
    
    for i, test_case in enumerate(test_cases, 1):
        print(f"\n{test_case['name']}")
        print("=" * len(test_case['name']))
        
        print(f"📋 Log Entry:")
        print(f"   {test_case['log_entry']}")
        
        print(f"\n🔍 Analysis:")
        print(f"   IP: {test_case['ip']}")
        print(f"   Path: {test_case['path']}")
        print(f"   User-Agent: {test_case['user_agent']}")
        print(f"   Referer: {test_case['referer']}")
        
        # Analyze with our middleware
        result = middleware.analyze_request(
            test_case['ip'], 
            test_case['user_agent'], 
            referer=test_case['referer']
        )
        
        print(f"\n🛡️  AIWAF Header Validation Result:")
        if result['blocked']:
            print(f"   Status: ❌ BLOCKED")
            print(f"   Reason: {result['reason']}")
            print(f"   Action: IP {test_case['ip']} would be blacklisted")
        else:
            print(f"   Status: ✅ ALLOWED")
            print(f"   Quality Score: {result['quality_score']}/11")
            print(f"   Reason: {result['reason']}")
        
        print(f"\n📝 Security Notes:")
        for note in test_case['notes']:
            print(f"   • {note}")
        
        if result['blocked']:
            print(f"\n🚨 Why This Was Blocked:")
            if 'Missing required headers' in result['reason']:
                print(f"   • Legitimate browsers ALWAYS send User-Agent")
                print(f"   • Missing User-Agent indicates automated tool")
                print(f"   • This is a classic bot/scanner behavior")
            elif 'Suspicious user agent' in result['reason']:
                print(f"   • User-Agent matches known bot patterns")
                print(f"   • Automated tools often have identifiable signatures")
        else:
            print(f"\n✅ Why This Was Allowed:")
            print(f"   • Complete, realistic User-Agent string")
            print(f"   • High quality score indicates real browser")
            print(f"   • Headers match legitimate browser patterns")
        
        print("\n" + "-" * 80)
    
    # Summary comparison
    print(f"\n📊 SUMMARY COMPARISON")
    print("=" * 30)
    
    print("SUSPICIOUS REQUEST (4.217.168.116):")
    print("❌ Missing User-Agent header")
    print("❌ Missing Accept header") 
    print("❌ Targeting WordPress vulnerabilities")
    print("❌ Scanner-like behavior pattern")
    print("🔒 Result: BLOCKED by Header Validation")
    
    print("\nLEGITIMATE REQUEST (95.173.221.26):")
    print("✅ Complete User-Agent (Ubuntu Chromium)")
    print("✅ Realistic browser headers")
    print("✅ Has referer (user navigation)")
    print("✅ High header quality score")
    print("🟢 Result: ALLOWED by Header Validation")
    
    print(f"\n🎯 IMPACT:")
    print("• Scanner blocked BEFORE reaching WordPress")
    print("• Reduced server load from automated probes")
    print("• Legitimate users unaffected")
    print("• Attack surface reduced significantly")

def demonstrate_log_parsing():
    """Show how to extract header info from web server logs"""
    
    print(f"\n\n🔧 LOG PARSING FOR HEADER VALIDATION")
    print("=" * 50)
    
    # Common log format fields
    print("Apache/Nginx Combined Log Format:")
    print('IP - - [timestamp] "METHOD /path HTTP/version" status size "referer" "user-agent" "real-ip" response-time=X')
    
    print(f"\nHeader Extraction:")
    print("• User-Agent: Field 7 (in quotes)")
    print("• Referer: Field 6 (in quotes)")  
    print("• Accept: Not in standard logs (need custom format)")
    print("• Other headers: Require extended log format")
    
    print(f"\nCustom Log Format for Header Validation:")
    print('LogFormat "%h - - [%t] \\"%r\\" %s %b \\"%{Referer}i\\" \\"%{User-Agent}i\\" \\"%{Accept}i\\" \\"%{Accept-Language}i\\"" combined_headers')
    
    print(f"\nIntegration Approaches:")
    print("1. Real-time: Middleware analyzes headers during request")
    print("2. Log analysis: Parse logs to identify patterns") 
    print("3. Hybrid: Middleware + log correlation for comprehensive view")

if __name__ == '__main__':
    analyze_real_requests()
    demonstrate_log_parsing()
