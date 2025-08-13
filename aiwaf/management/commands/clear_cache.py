#!/usr/bin/env python3

from django.core.management.base import BaseCommand
from django.core.cache import cache

class Command(BaseCommand):
    help = 'Clear Django cache'

    def handle(self, *args, **options):
        cache.clear()
        self.stdout.write(self.style.SUCCESS("✅ Django cache cleared successfully!"))
        
        # Also show what was cleared
        self.stdout.write("🧹 Cleared all cached data including:")
        self.stdout.write("   - Rate limiting data")
        self.stdout.write("   - Blacklist cache")
        self.stdout.write("   - AI anomaly data")
        self.stdout.write("   - Honeypot timing data")
