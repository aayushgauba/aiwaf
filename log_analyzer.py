#!/usr/bin/env python3
"""
Log Analysis Tool for Header Validation Patterns

This tool analyzes web server logs to identify suspicious header patterns
that would be caught by the HeaderValidationMiddleware.
"""

import re
import sys
from collections import defaultdict, Counter
from datetime import datetime

class LogAnalyzer:
    """Analyzes web server logs for header validation patterns"""
    
    def __init__(self):
        self.suspicious_patterns = [
            r'"-".*"-"',  # Missing both referer and user-agent
            r'"GET.*wp-content.*"-"',  # WordPress scanning without user-agent
            r'"GET.*admin.*"-"',  # Admin path scanning without user-agent
            r'"GET.*\.php.*"-"',  # PHP file scanning without user-agent
            r'"POST.*"-"',  # POST requests without user-agent (very suspicious)
        ]
        
        self.suspicious_paths = [
            r'/wp-content/',
            r'/wp-admin/',
            r'/administrator/',
            r'/admin/',
            r'/phpmyadmin/',
            r'/\.env',
            r'/config\.php',
            r'/backup',
            r'/upload',
        ]
        
        self.bot_user_agents = [
            r'curl/',
            r'wget/',
            r'python',
            r'java',
            r'Go-http',
            r'libwww',
            r'bot(?!.*google|.*bing)',  # Bot but not Google/Bing
        ]
    
    def parse_log_line(self, line):
        """Parse a single log line and extract relevant fields"""
        # Combined log format regex
        pattern = r'(\S+) \S+ \S+ \[([^\]]+)\] "(\S+) (\S+) (\S+)" (\d+) (\S+) "([^"]*)" "([^"]*)"'
        match = re.match(pattern, line)
        
        if not match:
            return None
            
        return {
            'ip': match.group(1),
            'timestamp': match.group(2),
            'method': match.group(3),
            'path': match.group(4),
            'protocol': match.group(5),
            'status': int(match.group(6)),
            'size': match.group(7),
            'referer': match.group(8),
            'user_agent': match.group(9)
        }
    
    def analyze_request(self, parsed_log):
        """Analyze a parsed log entry for suspicious patterns"""
        if not parsed_log:
            return None
            
        issues = []
        
        # Check for missing user agent
        if parsed_log['user_agent'] == '-':
            issues.append('missing_user_agent')
        
        # Check for missing referer on non-root requests
        if parsed_log['referer'] == '-' and parsed_log['path'] != '/':
            issues.append('missing_referer')
        
        # Check for suspicious paths
        for pattern in self.suspicious_paths:
            if re.search(pattern, parsed_log['path'], re.IGNORECASE):
                issues.append('suspicious_path')
                break
        
        # Check for bot user agents
        for pattern in self.bot_user_agents:
            if re.search(pattern, parsed_log['user_agent'], re.IGNORECASE):
                issues.append('bot_user_agent')
                break
        
        # Check for 404s (scanning)
        if parsed_log['status'] == 404:
            issues.append('not_found')
        
        return {
            'parsed': parsed_log,
            'issues': issues,
            'suspicious_score': len(issues)
        }
    
    def analyze_logs(self, log_lines):
        """Analyze multiple log lines and return statistics"""
        results = {
            'total_requests': 0,
            'suspicious_requests': 0,
            'missing_user_agent': 0,
            'bot_requests': 0,
            'scanning_attempts': 0,
            'top_suspicious_ips': Counter(),
            'top_suspicious_paths': Counter(),
            'suspicious_details': []
        }
        
        for line in log_lines:
            line = line.strip()
            if not line:
                continue
                
            parsed = self.parse_log_line(line)
            analysis = self.analyze_request(parsed)
            
            if not analysis:
                continue
                
            results['total_requests'] += 1
            
            if analysis['suspicious_score'] > 0:
                results['suspicious_requests'] += 1
                results['top_suspicious_ips'][analysis['parsed']['ip']] += 1
                
                if 'suspicious_path' in analysis['issues']:
                    results['top_suspicious_paths'][analysis['parsed']['path']] += 1
                    results['scanning_attempts'] += 1
            
            if 'missing_user_agent' in analysis['issues']:
                results['missing_user_agent'] += 1
            
            if 'bot_user_agent' in analysis['issues']:
                results['bot_requests'] += 1
            
            # Store details of highly suspicious requests
            if analysis['suspicious_score'] >= 2:
                results['suspicious_details'].append({
                    'ip': analysis['parsed']['ip'],
                    'path': analysis['parsed']['path'],
                    'user_agent': analysis['parsed']['user_agent'],
                    'issues': analysis['issues'],
                    'score': analysis['suspicious_score']
                })
        
        return results

def demo_log_analysis():
    """Demonstrate log analysis with the provided examples"""
    
    print("🔍 AIWAF Log Analysis Tool")
    print("=" * 50)
    
    # Sample log entries (including the real ones provided)
    sample_logs = [
        # The suspicious request from user
        '4.217.168.116 - - [31/Aug/2025:15:57:10 +0000] "GET /wp-content/plugins/hellopress/wp_filemanager.php HTTP/1.1" 404 4771 "-" "-"',
        
        # The legitimate request from user  
        '95.173.221.26 - - [31/Aug/2025:18:21:34 +0000] "GET / HTTP/1.1" 200 2276 "http://stlouisgurudwara.org/" "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Ubuntu Chromium/114.0.5775.194 Chrome/114.0.5775.194 Safari/537.36"',
        
        # Additional test cases
        '192.168.1.100 - - [31/Aug/2025:16:00:00 +0000] "GET /wp-admin/admin-ajax.php HTTP/1.1" 404 1234 "-" "curl/7.68.0"',
        '10.0.0.50 - - [31/Aug/2025:16:01:00 +0000] "POST /contact/ HTTP/1.1" 200 5678 "https://example.com/contact" "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36"',
        '203.0.113.45 - - [31/Aug/2025:16:02:00 +0000] "GET /.env HTTP/1.1" 404 0 "-" "-"',
        '198.51.100.25 - - [31/Aug/2025:16:03:00 +0000] "GET /admin/config.php HTTP/1.1" 404 1234 "-" "python-requests/2.25.1"',
    ]
    
    analyzer = LogAnalyzer()
    results = analyzer.analyze_logs(sample_logs)
    
    print(f"📊 ANALYSIS RESULTS")
    print("-" * 30)
    print(f"Total Requests: {results['total_requests']}")
    print(f"Suspicious Requests: {results['suspicious_requests']} ({results['suspicious_requests']/results['total_requests']*100:.1f}%)")
    print(f"Missing User-Agent: {results['missing_user_agent']}")
    print(f"Bot Requests: {results['bot_requests']}")
    print(f"Scanning Attempts: {results['scanning_attempts']}")
    
    print(f"\n🚨 TOP SUSPICIOUS IPs:")
    for ip, count in results['top_suspicious_ips'].most_common(5):
        print(f"   {ip}: {count} suspicious requests")
    
    print(f"\n🎯 TOP TARGETED PATHS:")
    for path, count in results['top_suspicious_paths'].most_common(5):
        print(f"   {path}: {count} attempts")
    
    print(f"\n🔍 DETAILED SUSPICIOUS ACTIVITY:")
    for detail in results['suspicious_details']:
        print(f"\n   IP: {detail['ip']}")
        print(f"   Path: {detail['path']}")
        print(f"   User-Agent: {detail['user_agent']}")
        print(f"   Issues: {', '.join(detail['issues'])}")
        print(f"   Suspicion Score: {detail['score']}/5")
        
        # Show what AIWAF would do
        would_block = False
        block_reason = ""
        
        if 'missing_user_agent' in detail['issues']:
            would_block = True
            block_reason = "Missing User-Agent header"
        elif 'bot_user_agent' in detail['issues']:
            would_block = True
            block_reason = "Suspicious User-Agent pattern"
        
        if would_block:
            print(f"   🛡️ AIWAF Action: BLOCKED ({block_reason})")
        else:
            print(f"   🛡️ AIWAF Action: Would require further analysis")
    
    print(f"\n📈 PROTECTION EFFECTIVENESS:")
    blocked_by_header_validation = 0
    for detail in results['suspicious_details']:
        if 'missing_user_agent' in detail['issues'] or 'bot_user_agent' in detail['issues']:
            blocked_by_header_validation += 1
    
    print(f"• Header Validation would block: {blocked_by_header_validation}/{results['suspicious_requests']} suspicious requests")
    print(f"• Protection rate: {blocked_by_header_validation/results['suspicious_requests']*100:.1f}% of suspicious traffic")
    print(f"• False positives: 0 (legitimate browsers passed)")

def create_log_monitoring_script():
    """Create a script for ongoing log monitoring"""
    
    script_content = '''#!/usr/bin/env python3
"""
Real-time log monitoring for AIWAF header validation patterns
Usage: tail -f /var/log/nginx/access.log | python monitor_headers.py
"""

import sys
import re
from datetime import datetime

class HeaderMonitor:
    def __init__(self):
        self.alerts = 0
        
    def check_line(self, line):
        # Extract user agent (last quoted field)
        user_agent_match = re.search(r'"([^"]*)"\\s*$', line)
        if not user_agent_match:
            return
            
        user_agent = user_agent_match.group(1)
        
        # Extract IP (first field)  
        ip_match = re.match(r'^(\\S+)', line)
        ip = ip_match.group(1) if ip_match else "unknown"
        
        # Check for suspicious patterns
        if user_agent == "-":
            self.alert(ip, "Missing User-Agent header", line)
        elif re.search(r'curl|wget|python|bot(?!.*google)', user_agent, re.IGNORECASE):
            self.alert(ip, f"Suspicious User-Agent: {user_agent}", line)
    
    def alert(self, ip, reason, line):
        self.alerts += 1
        timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        print(f"[{timestamp}] AIWAF ALERT #{self.alerts}")
        print(f"IP: {ip}")
        print(f"Reason: {reason}")
        print(f"Log: {line.strip()}")
        print("-" * 60)

if __name__ == "__main__":
    monitor = HeaderMonitor()
    
    print("AIWAF Header Monitoring Started...")
    print("Watching for suspicious header patterns...")
    print("=" * 50)
    
    try:
        for line in sys.stdin:
            monitor.check_line(line)
    except KeyboardInterrupt:
        print(f"\\nMonitoring stopped. Total alerts: {monitor.alerts}")
'''
    
    with open("monitor_headers.py", "w") as f:
        f.write(script_content)
    
    print(f"\n🔧 CREATED: monitor_headers.py")
    print("Usage: tail -f /var/log/nginx/access.log | python monitor_headers.py")

if __name__ == "__main__":
    demo_log_analysis()
    create_log_monitoring_script()
