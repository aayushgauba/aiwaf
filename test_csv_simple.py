#!/usr/bin/env python3
"""
Simple CSV Test Script
Test AI-WAF CSV functionality outside of Django
"""

import os
import csv
from datetime import datetime

def test_csv_operations():
    print("🧪 Testing AI-WAF CSV Operations")
    print("=" * 40)
    
    # Test directory creation
    test_dir = "test_aiwaf_data"
    if not os.path.exists(test_dir):
        os.makedirs(test_dir)
        print(f"✅ Created test directory: {test_dir}")
    else:
        print(f"✅ Test directory exists: {test_dir}")
    
    # Test CSV file creation and writing
    exemption_file = os.path.join(test_dir, "exemptions.csv")
    test_ip = "127.0.0.1"
    
    # Create/add exemption
    new_file = not os.path.exists(exemption_file)
    with open(exemption_file, "a", newline="", encoding="utf-8") as f:
        writer = csv.writer(f)
        if new_file:
            writer.writerow(["ip_address", "reason", "created_at"])
        writer.writerow([test_ip, "Test exemption", datetime.now().isoformat()])
    
    print(f"✅ Added {test_ip} to exemption file")
    
    # Test reading
    with open(exemption_file, "r", newline="", encoding="utf-8") as f:
        reader = csv.DictReader(f)
        found = False
        for row in reader:
            if row["ip_address"] == test_ip:
                found = True
                print(f"✅ Found exemption: {row}")
                break
        
        if not found:
            print(f"❌ Could not find {test_ip} in exemption file")
    
    # Test file contents
    with open(exemption_file, "r", encoding="utf-8") as f:
        content = f.read()
        print(f"\n📄 File contents:\n{content}")
    
    # Cleanup
    import shutil
    shutil.rmtree(test_dir)
    print(f"🧹 Cleaned up test directory")

if __name__ == "__main__":
    test_csv_operations()
