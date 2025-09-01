#!/usr/bin/env python3
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
        user_agent_match = re.search(r'"([^"]*)"\s*$', line)
        if not user_agent_match:
            return
            
        user_agent = user_agent_match.group(1)
        
        # Extract IP (first field)  
        ip_match = re.match(r'^(\S+)', line)
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
        print(f"\nMonitoring stopped. Total alerts: {monitor.alerts}")
