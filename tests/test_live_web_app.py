#!/usr/bin/env python3
"""
Live Web App Test for AIWAF Keyword Storage
Use this script to test keyword learning on a running web application.
This can be used with curl, requests, or any HTTP client.
"""

import requests
import time
import json
import os
from datetime import datetime

class WebAppStorageTest:
    """Test AIWAF keyword storage on a live web application"""
    
    def __init__(self, base_url, fallback_storage_path=None):
        """
        Initialize the test
        
        Args:
            base_url: Base URL of your web application (e.g., 'http://localhost:8000')
            fallback_storage_path: Path to aiwaf/fallback_keywords.json file
        """
        self.base_url = base_url.rstrip('/')
        self.fallback_storage_path = fallback_storage_path or 'aiwaf/fallback_keywords.json'
        self.session = requests.Session()
        
    def get_keyword_count(self):
        """Get current number of stored keywords"""
        try:
            if os.path.exists(self.fallback_storage_path):
                with open(self.fallback_storage_path, 'r') as f:
                    data = json.load(f)
                return len(data), data
            return 0, {}
        except Exception as e:
            print(f"Error reading storage file: {e}")
            return 0, {}
    
    def make_request(self, path, method='GET', params=None, expect_status=None):
        """Make a request to the web app and return response info"""
        url = f"{self.base_url}{path}"
        
        try:
            if method.upper() == 'GET':
                response = self.session.get(url, params=params, timeout=10)
            elif method.upper() == 'POST':
                response = self.session.post(url, data=params, timeout=10)
            else:
                response = self.session.request(method, url, timeout=10)
            
            return {
                'url': url,
                'status_code': response.status_code,
                'success': True,
                'response_time': response.elapsed.total_seconds()
            }
        except requests.exceptions.RequestException as e:
            return {
                'url': url,
                'status_code': None,
                'success': False,
                'error': str(e),
                'response_time': None
            }
    
    def test_malicious_requests(self):
        """Send various malicious requests to trigger keyword learning"""
        
        print(f"🌐 Testing AIWAF Keyword Storage on Web App")
        print(f"📍 Target: {self.base_url}")
        print(f"💾 Storage: {self.fallback_storage_path}")
        print("=" * 60)
        
        # Get baseline keyword count
        initial_count, initial_keywords = self.get_keyword_count()
        print(f"📊 Initial keyword count: {initial_count}")
        if initial_keywords:
            print(f"   Existing keywords: {list(initial_keywords.keys())[:5]}{'...' if len(initial_keywords) > 5 else ''}")
        
        print(f"\n🎯 Sending malicious requests to trigger learning...")
        
        # Test scenarios designed to trigger keyword learning
        test_requests = [
            # WordPress attacks
            {'path': '/wp-admin/', 'description': 'WordPress admin access'},
            {'path': '/wp-admin/admin-ajax.php', 'description': 'WordPress AJAX endpoint'},
            {'path': '/wp-login.php', 'description': 'WordPress login'},
            {'path': '/wp-content/themes/exploit.php', 'description': 'WordPress theme exploit'},
            
            # Config file discovery
            {'path': '/.env', 'description': 'Environment file'},
            {'path': '/config/database.yml', 'description': 'Database config'},
            {'path': '/config.php', 'description': 'PHP config'},
            {'path': '/configuration.php', 'description': 'Configuration file'},
            
            # Directory traversal
            {'path': '/../../../etc/passwd', 'description': 'Directory traversal'},
            {'path': '/app/../config/secrets.yml', 'description': 'Path traversal to config'},
            
            # PHP/Admin tools
            {'path': '/phpinfo.php', 'description': 'PHP info page'},
            {'path': '/phpmyadmin/', 'description': 'phpMyAdmin'},
            {'path': '/phpmyadmin/index.php', 'description': 'phpMyAdmin index'},
            {'path': '/adminer.php', 'description': 'Adminer tool'},
            
            # Backup files
            {'path': '/backup.sql', 'description': 'SQL backup'},
            {'path': '/database.bak', 'description': 'Database backup'},
            {'path': '/site_backup.tar.gz', 'description': 'Site backup'},
            {'path': '/backup/users.sql', 'description': 'User backup'},
            
            # SQL injection attempts
            {'path': '/search.php', 'params': {'q': "1' UNION SELECT * FROM users--"}, 'description': 'SQL injection'},
            {'path': '/login.php', 'params': {'user': "admin' OR 1=1--"}, 'description': 'Login SQL injection'},
            
            # Script execution attempts
            {'path': '/shell.php', 'description': 'Web shell'},
            {'path': '/cmd.php', 'params': {'cmd': 'ls -la'}, 'description': 'Command execution'},
        ]
        
        results = []
        successful_requests = 0
        
        for i, test in enumerate(test_requests, 1):
            path = test['path']
            params = test.get('params')
            description = test['description']
            
            print(f"\n{i:2d}. {description}")
            print(f"    URL: {self.base_url}{path}")
            
            # Make the request
            result = self.make_request(path, params=params)
            results.append({**result, 'description': description})
            
            if result['success']:
                successful_requests += 1
                status_icon = "✅" if result['status_code'] == 404 else "📝"
                print(f"    {status_icon} Status: {result['status_code']} ({result['response_time']:.2f}s)")
            else:
                print(f"    ❌ Error: {result['error']}")
            
            # Small delay to avoid overwhelming the server
            time.sleep(0.5)
        
        print(f"\n📊 Request Summary:")
        print(f"   Total requests sent: {len(test_requests)}")
        print(f"   Successful requests: {successful_requests}")
        
        # Check keyword learning results
        print(f"\n⏳ Waiting 2 seconds for middleware processing...")
        time.sleep(2)
        
        final_count, final_keywords = self.get_keyword_count()
        new_keywords = final_count - initial_count
        
        print(f"\n💾 Storage Results:")
        print(f"   Initial keywords: {initial_count}")
        print(f"   Final keywords: {final_count}")
        print(f"   New keywords learned: {new_keywords}")
        
        if new_keywords > 0:
            print(f"   ✅ SUCCESS: Keyword learning is working!")
            
            # Show new keywords
            new_keyword_list = []
            for keyword, count in final_keywords.items():
                if keyword not in initial_keywords:
                    new_keyword_list.append(f"{keyword}({count})")
            
            if new_keyword_list:
                print(f"   📝 New keywords: {', '.join(new_keyword_list[:10])}")
                if len(new_keyword_list) > 10:
                    print(f"      ... and {len(new_keyword_list) - 10} more")
        else:
            print(f"   ⚠️  No new keywords learned")
            print(f"   💡 This could mean:")
            print(f"      - Middleware not configured or not running")
            print(f"      - Requests hitting legitimate paths")
            print(f"      - Learning conditions too restrictive")
            print(f"      - Storage not properly configured")
        
        return new_keywords > 0, results
    
    def test_legitimate_requests(self):
        """Test that legitimate requests don't trigger learning"""
        print(f"\n🔒 Testing Legitimate Requests (Should NOT learn keywords):")
        
        initial_count, _ = self.get_keyword_count()
        
        legitimate_requests = [
            {'path': '/', 'description': 'Home page'},
            {'path': '/about/', 'description': 'About page'},
            {'path': '/contact/', 'description': 'Contact page'},
            {'path': '/api/health/', 'description': 'API health check'},
            {'path': '/static/css/style.css', 'description': 'Static CSS file'},
        ]
        
        for test in legitimate_requests:
            result = self.make_request(test['path'])
            status_icon = "✅" if result['success'] else "❌"
            print(f"   {status_icon} {test['description']}: {result.get('status_code', 'Error')}")
        
        time.sleep(1)
        final_count, _ = self.get_keyword_count()
        
        if final_count == initial_count:
            print(f"   ✅ Good: No keywords learned from legitimate requests")
        else:
            print(f"   ⚠️  Warning: {final_count - initial_count} keywords learned from legitimate requests")
    
    def generate_report(self):
        """Generate a detailed test report"""
        count, keywords = self.get_keyword_count()
        
        print(f"\n📋 AIWAF Storage Test Report")
        print(f"🕒 Generated: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
        print("=" * 60)
        
        if count > 0:
            print(f"📊 Storage Statistics:")
            print(f"   Total unique keywords: {count}")
            print(f"   Total occurrences: {sum(keywords.values())}")
            
            # Top keywords by frequency
            sorted_keywords = sorted(keywords.items(), key=lambda x: x[1], reverse=True)
            print(f"\n🔝 Top Keywords by Frequency:")
            for keyword, freq in sorted_keywords[:10]:
                print(f"   {keyword}: {freq} occurrences")
            
            # Analyze attack patterns
            attack_patterns = {
                'WordPress': [k for k in keywords.keys() if any(wp in k.lower() for wp in ['wp', 'wordpress'])],
                'Config/Database': [k for k in keywords.keys() if any(cfg in k.lower() for cfg in ['config', 'database', 'env'])],
                'Admin Tools': [k for k in keywords.keys() if any(admin in k.lower() for admin in ['admin', 'phpmyadmin', 'adminer'])],
                'Backup Files': [k for k in keywords.keys() if 'backup' in k.lower()],
                'Scripts/PHP': [k for k in keywords.keys() if any(script in k.lower() for script in ['php', 'script', 'shell'])],
            }
            
            print(f"\n🎯 Attack Pattern Analysis:")
            for pattern, keywords_list in attack_patterns.items():
                if keywords_list:
                    print(f"   {pattern}: {len(keywords_list)} keywords")
                    print(f"      Examples: {', '.join(keywords_list[:3])}")
        else:
            print(f"📊 No keywords stored yet")
            print(f"💡 This could indicate:")
            print(f"   - AIWAF middleware not installed/configured")
            print(f"   - Web app not receiving malicious requests")
            print(f"   - Storage configuration issues")

def main():
    """Main test function"""
    print("🔧 AIWAF Live Web App Storage Test")
    print("=" * 50)
    
    # Configuration
    print("📋 Configuration:")
    base_url = input("Enter your web app URL (e.g., http://localhost:8000): ").strip()
    if not base_url:
        base_url = "http://localhost:8000"
        print(f"Using default: {base_url}")
    
    storage_path = input("Enter fallback storage path (or press Enter for default): ").strip()
    if not storage_path:
        storage_path = "aiwaf/fallback_keywords.json"
    
    print(f"\n🎯 Test Configuration:")
    print(f"   Target URL: {base_url}")
    print(f"   Storage path: {storage_path}")
    
    # Initialize tester
    tester = WebAppStorageTest(base_url, storage_path)
    
    # Run tests
    try:
        success, results = tester.test_malicious_requests()
        tester.test_legitimate_requests()
        tester.generate_report()
        
        print(f"\n🎉 Test Complete!")
        if success:
            print(f"   ✅ AIWAF keyword storage is working correctly!")
        else:
            print(f"   ⚠️  Keyword storage may not be working - check configuration")
            
    except KeyboardInterrupt:
        print(f"\n⏹️  Test interrupted by user")
    except Exception as e:
        print(f"\n❌ Test failed with error: {e}")

if __name__ == "__main__":
    main()
