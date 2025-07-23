from django.core.management.base import BaseCommand, CommandError
from aiwaf.models import IPExemption

class Command(BaseCommand):
    help = 'Add an IP address to the IPExemption list (prevents blacklisting)'

    def add_arguments(self, parser):
        parser.add_argument('ip', type=str, help='IP address to exempt')
        parser.add_argument('--reason', type=str, default='', help='Reason for exemption (optional)')

    def handle(self, *args, **options):
        ip = options['ip']
        reason = options['reason']
        obj, created = IPExemption.objects.get_or_create(ip_address=ip, defaults={'reason': reason})
        if not created:
            self.stdout.write(self.style.WARNING(f'IP {ip} is already exempted.'))
        else:
            self.stdout.write(self.style.SUCCESS(f'IP {ip} added to exemption list.'))
        if reason:
            obj.reason = reason
            obj.save()
            self.stdout.write(self.style.SUCCESS(f'Reason set to: {reason}'))
