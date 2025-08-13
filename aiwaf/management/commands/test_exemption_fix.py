#!/usr/bin/env python3

from django.core.management.base import BaseCommand
from aiwaf.blacklist_manager import BlacklistManager
from aiwaf.storage import get_exemption_store

class Command(BaseCommand):
    help = 'Test that exempted IPs are properly honored by BlacklistManager'

    def add_arguments(self, parser):
        parser.add_argument('--ip', default='97.187.30.95', help='IP address to test')

    def handle(self, *args, **options):
        test_ip = options['ip']
        
        self.stdout.write(f"\n=== Testing Exemption Fix for IP: {test_ip} ===")
        
        # Check exemption store
        exemption_store = get_exemption_store()
        is_exempted = exemption_store.is_exempted(test_ip)
        self.stdout.write(f"1. Is IP exempted in storage? {is_exempted}")
        
        # Test BlacklistManager.block() - should not block exempted IPs
        self.stdout.write(f"\n2. Testing BlacklistManager.block() on exempted IP...")
        BlacklistManager.block(test_ip, "Test block attempt")
        
        # Check if actually blocked
        is_blocked = BlacklistManager.is_blocked(test_ip)
        self.stdout.write(f"3. Is IP blocked after block attempt? {is_blocked}")
        
        if is_exempted and not is_blocked:
            self.stdout.write(self.style.SUCCESS("✅ PASS: Exempted IP was NOT blocked"))
        elif is_exempted and is_blocked:
            self.stdout.write(self.style.ERROR("❌ FAIL: Exempted IP was blocked (this should not happen)"))
        elif not is_exempted:
            self.stdout.write(self.style.WARNING("⚠️  IP is not exempted, blocking behavior is normal"))
        
        # Test with a non-exempted IP to verify blocking still works
        test_non_exempted = "1.2.3.4"
        self.stdout.write(f"\n4. Testing with non-exempted IP: {test_non_exempted}")
        
        is_exempted_2 = exemption_store.is_exempted(test_non_exempted)
        self.stdout.write(f"   Is non-exempted IP exempted? {is_exempted_2}")
        
        BlacklistManager.block(test_non_exempted, "Test block non-exempted")
        is_blocked_2 = BlacklistManager.is_blocked(test_non_exempted)
        self.stdout.write(f"   Is non-exempted IP blocked? {is_blocked_2}")
        
        if not is_exempted_2 and is_blocked_2:
            self.stdout.write(self.style.SUCCESS("✅ PASS: Non-exempted IP was properly blocked"))
        else:
            self.stdout.write(self.style.ERROR("❌ FAIL: Non-exempted IP blocking failed"))
        
        self.stdout.write(f"\n=== Test Complete ===")
