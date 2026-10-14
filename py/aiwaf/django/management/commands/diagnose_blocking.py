#!/usr/bin/env python3

from django.core.management.base import BaseCommand
from django.core.cache import cache
from aiwaf.django.blocklist_manager import BlocklistManager
from aiwaf.django.storage import get_exemption_store, get_blocklist_store
from aiwaf.django.utils import get_ip
from django.test import RequestFactory

class Command(BaseCommand):
    help = 'Comprehensive diagnosis of blocking issues'

    def add_arguments(self, parser):
        parser.add_argument('--ip', default='97.187.30.95', help='IP address to test')
        parser.add_argument('--clear-cache', action='store_true', help='Clear Django cache')

    def handle(self, *args, **options):
        test_ip = options['ip']
        
        self.stdout.write(f"\n Comprehensive Blocking Diagnosis for IP: {test_ip}")
        self.stdout.write("=" * 60)
        
        if options['clear_cache']:
            cache.clear()
            self.stdout.write(" Cleared Django cache")
        
        # 1. Check exemption status
        exemption_store = get_exemption_store()
        is_exempted = exemption_store.is_exempted(test_ip)
        self.stdout.write(f"1.  IP exempted in storage: {is_exempted}")
        
        # 2. Check blocklist status
        blocklist_store = get_blocklist_store()
        is_in_blocklist = blocklist_store.is_blocked(test_ip)
        self.stdout.write(f"2.  IP in blocklist storage: {is_in_blocklist}")
        
        # 3. Check BlocklistManager final decision
        manager_blocked = BlocklistManager.is_blocked(test_ip)
        self.stdout.write(f"3.  BlocklistManager says blocked: {manager_blocked}")
        
        # 4. Check Django cache for blocklist entries
        cache_key = f"blocklist:{test_ip}"
        cached_value = cache.get(cache_key)
        self.stdout.write(f"4.  Cache value for blocklist:{test_ip}: {cached_value}")
        
        # 5. Test what IP would be detected from a request
        factory = RequestFactory()
        
        # Test different scenarios
        scenarios = [
            ("Direct IP", {'REMOTE_ADDR': test_ip}),
            ("X-Forwarded-For", {'HTTP_X_FORWARDED_FOR': test_ip}),
            ("X-Real-IP", {'HTTP_X_REAL_IP': test_ip}),
            ("CloudFlare", {'HTTP_CF_CONNECTING_IP': test_ip}),
        ]
        
        self.stdout.write(f"\n5.  IP Detection Tests:")
        for name, meta in scenarios:
            request = factory.get('/', **meta)
            detected_ip = get_ip(request)
            self.stdout.write(f"   {name}: {detected_ip}")
            if detected_ip == test_ip:
                self.stdout.write(f"    Match!")
            
        # 6. Check rate limiting cache entries
        self.stdout.write(f"\n6.  Rate Limiting Cache Entries:")
        rate_keys = [
            f"ratelimit:{test_ip}",
            f"aiwaf:{test_ip}",
            f"honeypot_get:{test_ip}"
        ]
        
        for key in rate_keys:
            value = cache.get(key)
            if value:
                self.stdout.write(f"   {key}: {value}")
            else:
                self.stdout.write(f"   {key}: None")
        
        # 7. Summary
        self.stdout.write(f"\n SUMMARY:")
        if is_exempted and not manager_blocked:
            self.stdout.write(self.style.SUCCESS(" IP should NOT be blocked"))
            if options.get('still_blocked'):
                self.stdout.write(self.style.WARNING("  If still blocked, check:"))
                self.stdout.write("   - Web server logs (nginx, apache)")
                self.stdout.write("   - Other middleware or security software")
                self.stdout.write("   - Browser cache/cookies")
        elif not is_exempted:
            self.stdout.write(self.style.WARNING(f"  IP {test_ip} is NOT exempted"))
        elif manager_blocked:
            self.stdout.write(self.style.ERROR(f" IP is being blocked despite exemption"))
        
        self.stdout.write(f"\n To clear all caches and reset:")
        self.stdout.write(f"   python manage.py shell -c \"from django.core.cache import cache; cache.clear()\"")
        self.stdout.write(f"=" * 60)


# Compatibility aliases for callers using the previous terminology.
BlacklistManager = BlocklistManager
get_blacklist_store = get_blocklist_store
