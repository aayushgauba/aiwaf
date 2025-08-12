from django.core.management.base import BaseCommand
from aiwaf.models import BlacklistEntry, IPExemption

class Command(BaseCommand):
    help = 'Reset AI-WAF by clearing all blacklist and exemption (whitelist) entries'

    def add_arguments(self, parser):
        parser.add_argument(
            '--blacklist-only',
            action='store_true',
            help='Clear only blacklist entries, keep exemptions'
        )
        parser.add_argument(
            '--exemptions-only',
            action='store_true',
            help='Clear only exemption entries, keep blacklist'
        )
        parser.add_argument(
            '--confirm',
            action='store_true',
            help='Skip confirmation prompt'
        )

    def handle(self, *args, **options):
        blacklist_only = options['blacklist_only']
        exemptions_only = options['exemptions_only']
        confirm = options['confirm']
        
        # Count current entries
        blacklist_count = BlacklistEntry.objects.count()
        exemption_count = IPExemption.objects.count()
        
        if blacklist_only and exemptions_only:
            self.stdout.write(self.style.ERROR('Cannot use both --blacklist-only and --exemptions-only flags'))
            return
        
        # Determine what to clear
        if blacklist_only:
            action = f"Clear {blacklist_count} blacklist entries"
            clear_blacklist = True
            clear_exemptions = False
        elif exemptions_only:
            action = f"Clear {exemption_count} exemption entries"
            clear_blacklist = False
            clear_exemptions = True
        else:
            action = f"Clear {blacklist_count} blacklist entries and {exemption_count} exemption entries"
            clear_blacklist = True
            clear_exemptions = True
        
        # Show what will be cleared
        self.stdout.write(f"AI-WAF Reset: {action}")
        
        if not confirm:
            response = input("Are you sure you want to proceed? [y/N]: ")
            if response.lower() not in ['y', 'yes']:
                self.stdout.write(self.style.WARNING('Operation cancelled'))
                return
        
        # Perform the reset
        deleted_counts = {'blacklist': 0, 'exemptions': 0}
        
        if clear_blacklist:
            deleted_counts['blacklist'], _ = BlacklistEntry.objects.all().delete()
        
        if clear_exemptions:
            deleted_counts['exemptions'], _ = IPExemption.objects.all().delete()
        
        # Report results
        if clear_blacklist and clear_exemptions:
            self.stdout.write(
                self.style.SUCCESS(
                    f"✅ Reset complete: Deleted {deleted_counts['blacklist']} blacklist entries "
                    f"and {deleted_counts['exemptions']} exemption entries"
                )
            )
        elif clear_blacklist:
            self.stdout.write(
                self.style.SUCCESS(f"✅ Blacklist cleared: Deleted {deleted_counts['blacklist']} entries")
            )
        elif clear_exemptions:
            self.stdout.write(
                self.style.SUCCESS(f"✅ Exemptions cleared: Deleted {deleted_counts['exemptions']} entries")
            )
