#!/usr/bin/env python3
"""
Simple Exemption Test
Run this to test AI-WAF exemption functionality
Usage: python test_exemption_simple.py
"""

def test_exemption_functionality():
    print("AI-WAF Exemption Test")
    print("=" * 30)
    
    # Test IP
    test_ip = "192.168.1.100"
    
    try:
        # Import Django and configure minimal settings
        import os
        import django
        from django.conf import settings
        
        if not settings.configured:
            settings.configure(
                DEBUG=True,
                AIWAF_STORAGE_MODE="csv",
                AIWAF_CSV_DATA_DIR="test_aiwaf_data",
                SECRET_KEY="test-key-for-exemption-test"
            )
            django.setup()
        
        print(f"Django configured")
        print(f"Storage Mode: {getattr(settings, 'AIWAF_STORAGE_MODE', 'not set')}")
        print(f"CSV Directory: {getattr(settings, 'AIWAF_CSV_DATA_DIR', 'not set')}")
        print("")
        
        # Test storage factory
        from aiwaf.storage import get_exemption_store
        exemption_store = get_exemption_store()
        
        print(f"Storage factory returned: {exemption_store.__name__}")
        print("")
        
        # Test adding exemption
        print(f"Adding {test_ip} to exemption list...")
        exemption_store.add_ip(test_ip, "Test exemption")
        print("Added exemption")
        
        # Test checking exemption
        print(f"Checking if {test_ip} is exempted...")
        is_exempted = exemption_store.is_exempted(test_ip)
        print(f"Result: {is_exempted}")
        
        if is_exempted:
            print("SUCCESS: Exemption is working!")
        else:
            print("FAILURE: Exemption is NOT working!")
            
        # Test utils function
        print(f"\nTesting utils function...")
        from aiwaf.utils import is_ip_exempted
        is_exempted_utils = is_ip_exempted(test_ip)
        print(f"Utils result: {is_exempted_utils}")
        
        if is_exempted_utils:
            print("SUCCESS: Utils exemption is working!")
        else:
            print("FAILURE: Utils exemption is NOT working!")
        
        # Show all exemptions
        print(f"\nAll exemptions:")
        all_exemptions = exemption_store.get_all()
        for exemption in all_exemptions:
            if isinstance(exemption, dict):
                ip = exemption.get('ip_address', 'N/A')
                reason = exemption.get('reason', 'No reason')
                print(f"  - {ip}: {reason}")
            else:
                print(f"  - {exemption}")
        
        # Cleanup
        import shutil
        test_dir = getattr(settings, 'AIWAF_CSV_DATA_DIR', 'test_aiwaf_data')
        if os.path.exists(test_dir):
            shutil.rmtree(test_dir)
            print(f"\nCleaned up test directory: {test_dir}")
            
    except Exception as e:
        print(f"Test failed with error: {e}")
        import traceback
        traceback.print_exc()

if __name__ == "__main__":
    test_exemption_functionality()
