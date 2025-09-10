# AI-WAF Middleware Logger Test Script

"""
This script demonstrates the AI-WAF middleware logger functionality.
It shows how requests are captured and how the CSV logs can be used for training.
"""

import os
import csv
import tempfile
from datetime import datetime

# Simulate middleware logger CSV output
def create_sample_csv_log():
    """Create a sample CSV log file to demonstrate the format"""
    
    # Create temporary CSV file
    temp_file = tempfile.NamedTemporaryFile(mode='w', suffix='.csv', delete=False)
    
    # Write header
    writer = csv.writer(temp_file)
    writer.writerow([
        'timestamp', 'ip_address', 'method', 'path', 'status_code', 
        'response_time', 'user_agent', 'referer', 'content_length'
    ])
    
    # Sample request data
    sample_requests = [
        # Normal requests
        ['12/Aug/2025:14:30:15 +0000', '192.168.1.100', 'GET', '/', '200', '0.145', 'Mozilla/5.0 (Windows NT 10.0; Win64; x64)', '-', '1234'],
        ['12/Aug/2025:14:30:16 +0000', '192.168.1.100', 'GET', '/about/', '200', '0.089', 'Mozilla/5.0 (Windows NT 10.0; Win64; x64)', 'http://example.com/', '987'],
        ['12/Aug/2025:14:30:17 +0000', '192.168.1.100', 'POST', '/contact/', '200', '0.234', 'Mozilla/5.0 (Windows NT 10.0; Win64; x64)', 'http://example.com/about/', '456'],
        
        # Suspicious requests (potential attacks)
        ['12/Aug/2025:14:31:20 +0000', '10.0.0.50', 'GET', '/admin.php', '404', '0.012', 'curl/7.68.0', '-', '123'],
        ['12/Aug/2025:14:31:21 +0000', '10.0.0.50', 'GET', '/wp-admin/', '404', '0.015', 'curl/7.68.0', '-', '123'],
        ['12/Aug/2025:14:31:22 +0000', '10.0.0.50', 'GET', '/.env', '404', '0.008', 'curl/7.68.0', '-', '123'],
        ['12/Aug/2025:14:31:23 +0000', '10.0.0.50', 'GET', '/shell.php', '404', '0.011', 'curl/7.68.0', '-', '123'],
        ['12/Aug/2025:14:31:24 +0000', '10.0.0.50', 'GET', '/config.bak', '404', '0.009', 'curl/7.68.0', '-', '123'],
        
        # More normal requests
        ['12/Aug/2025:14:32:30 +0000', '203.0.113.45', 'GET', '/api/users/', '200', '0.156', 'MyApp/1.0', '-', '2048'],
        ['12/Aug/2025:14:32:31 +0000', '203.0.113.45', 'GET', '/api/products/', '200', '0.298', 'MyApp/1.0', '-', '4096'],
    ]
    
    # Write sample data
    for request in sample_requests:
        writer.writerow(request)
    
    temp_file.close()
    return temp_file.name

def demonstrate_csv_parsing(csv_file):
    """Demonstrate parsing CSV log for AI-WAF training"""
    
    print("📋 AI-WAF Middleware CSV Log Contents:")
    print("=" * 50)
    
    with open(csv_file, 'r', newline='', encoding='utf-8') as f:
        reader = csv.DictReader(f)
        for i, row in enumerate(reader, 1):
            print(f"{i:2d}. {row['timestamp']} | {row['ip_address']:15s} | {row['method']:4s} | {row['path']:20s} | {row['status_code']} | {row['response_time']}s")
    
    print("\n🔍 Analysis:")
    print("=" * 50)
    
    # Count by IP
    ip_counts = {}
    status_counts = {}
    suspicious_paths = []
    
    with open(csv_file, 'r', newline='', encoding='utf-8') as f:
        reader = csv.DictReader(f)
        for row in reader:
            ip = row['ip_address']
            status = row['status_code']
            path = row['path']
            
            ip_counts[ip] = ip_counts.get(ip, 0) + 1
            status_counts[status] = status_counts.get(status, 0) + 1
            
            # Check for suspicious paths
            suspicious_keywords = ['.php', 'wp-', '.env', '.git', '.bak', 'shell', 'admin.php']
            if any(keyword in path.lower() for keyword in suspicious_keywords):
                suspicious_paths.append((ip, path))
    
    print("IP Request Counts:")
    for ip, count in sorted(ip_counts.items()):
        print(f"  {ip:15s}: {count} requests")
    
    print(f"\nStatus Code Distribution:")
    for status, count in sorted(status_counts.items()):
        print(f"  {status}: {count} requests")
    
    print(f"\nSuspicious Paths Detected:")
    for ip, path in suspicious_paths:
        print(f"  {ip:15s} → {path}")
    
    print(f"\n🤖 AI-WAF Training Insights:")
    print("=" * 50)
    print(f"• IP 10.0.0.50 shows scanning behavior (5 requests to non-existent files)")
    print(f"• Keywords detected: admin.php, wp-admin, .env, shell.php, config.bak") 
    print(f"• Response times for 404s are very fast (0.008-0.015s) indicating automated scanning")
    print(f"• This data would be used to train the AI model to detect similar patterns")

def show_integration_example():
    """Show how the middleware integrates with AI-WAF"""
    
    print("\n🔗 Integration with AI-WAF Training:")
    print("=" * 50)
    
    example_code = '''
# In trainer.py, when main access log is unavailable:

def _read_all_logs() -> list[str]:
    lines = []
    
    # Try main access log first
    if LOG_PATH and os.path.exists(LOG_PATH):
        # ... read main log ...
    
    # Fallback to middleware CSV log
    if not lines:
        middleware_csv = "aiwaf_requests.csv"
        if os.path.exists(middleware_csv):
            from .middleware_logger import AIWAFCSVLogParser
            csv_lines = AIWAFCSVLogParser.get_log_lines_for_trainer(middleware_csv)
            lines.extend(csv_lines)
            print(f"📋 Using AI-WAF middleware CSV log: {len(csv_lines)} entries")
    
    return lines
'''
    
    print(example_code)
    
    print("\n⚙️ Settings Configuration:")
    print("=" * 50)
    
    settings_example = '''
# In your Django settings.py:

# Enable middleware logging
AIWAF_MIDDLEWARE_LOGGING = True
AIWAF_MIDDLEWARE_LOG = "aiwaf_requests.log"
AIWAF_MIDDLEWARE_CSV = True  # Use CSV format

# Add to MIDDLEWARE
MIDDLEWARE = [
    # ... other middleware ...
    'aiwaf.middleware_logger.AIWAFLoggerMiddleware',
]
'''
    
    print(settings_example)

if __name__ == "__main__":
    print("🛡️  AI-WAF Middleware Logger Demonstration")
    print("=" * 60)
    
    # Create sample CSV log
    csv_file = create_sample_csv_log()
    
    try:
        # Demonstrate parsing
        demonstrate_csv_parsing(csv_file)
        
        # Show integration
        show_integration_example()
        
        print(f"\n📁 Sample CSV file created at: {csv_file}")
        print("You can examine this file to see the exact format used by AI-WAF middleware logger.")
        
    finally:
        # Clean up
        if os.path.exists(csv_file):
            os.unlink(csv_file)
