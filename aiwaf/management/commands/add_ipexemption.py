from django.core.management.base import BaseCommand, CommandError
from aiwaf.storage import get_exemption_store

class Command(BaseCommand):
    help = 'Add an IP address to the IPExemption list (prevents blacklisting)'

    def add_arguments(self, parser):
        parser.add_argument('ip', type=str, help='IP address to exempt')
        parser.add_argument('--reason', type=str, default='', help='Reason for exemption (optional)')

    def handle(self, *args, **options):
        ip = options['ip']
        reason = options['reason']
        
        store = get_exemption_store()
        
        if store.is_exempted(ip):
            self.stdout.write(self.style.WARNING(f'IP {ip} is already exempted.'))
        else:
            store.add_exemption(ip, reason)
            self.stdout.write(self.style.SUCCESS(f'IP {ip} added to exemption list.'))
            if reason:
                self.stdout.write(self.style.SUCCESS(f'Reason: {reason}'))
