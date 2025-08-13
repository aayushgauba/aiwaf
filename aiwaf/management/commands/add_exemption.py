#!/usr/bin/env python3

from django.core.management.base import BaseCommand
from aiwaf.storage import get_exemption_store

class Command(BaseCommand):
    help = 'Add IP to exemption list using Django models'

    def add_arguments(self, parser):
        parser.add_argument('ip', help='IP address to exempt')
        parser.add_argument('--reason', default='Manual exemption', help='Reason for exemption')

    def handle(self, *args, **options):
        ip = options['ip']
        reason = options['reason']
        
        self.stdout.write(f"Adding IP {ip} to exemption list...")
        
        exemption_store = get_exemption_store()
        exemption_store.add_exemption(ip, reason)
        
        # Verify it was added
        if exemption_store.is_exempted(ip):
            self.stdout.write(self.style.SUCCESS(f"✅ Successfully exempted IP: {ip}"))
        else:
            self.stdout.write(self.style.ERROR(f"❌ Failed to exempt IP: {ip}"))
        
        # Show all exempted IPs
        all_exempted = exemption_store.get_all_exempted_ips()
        self.stdout.write(f"\nAll exempted IPs: {all_exempted}")
