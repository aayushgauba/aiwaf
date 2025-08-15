from django.core.management.base import BaseCommand
from aiwaf.storage import get_blacklist_store, get_exemption_store
import sys

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
        
        try:
            blacklist_store = get_blacklist_store()
            exemption_store = get_exemption_store()
        except Exception as e:
            self.stdout.write(self.style.ERROR(f'Error initializing stores: {e}'))
            return
        
        # Count current entries safely
        try:
            blacklist_entries = blacklist_store.get_all()
            blacklist_count = len(blacklist_entries)
        except Exception as e:
            self.stdout.write(self.style.WARNING(f'Warning: Could not count blacklist entries: {e}'))
            blacklist_count = 0
            blacklist_entries = []
        
        try:
            exemption_entries = exemption_store.get_all()
            exemption_count = len(exemption_entries)
        except Exception as e:
            self.stdout.write(self.style.WARNING(f'Warning: Could not count exemption entries: {e}'))
            exemption_count = 0
            exemption_entries = []
        
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
            try:
                response = input("Are you sure you want to proceed? [y/N]: ")
                if response.lower() not in ['y', 'yes']:
                    self.stdout.write(self.style.WARNING('Operation cancelled'))
                    return
            except (EOFError, KeyboardInterrupt):
                self.stdout.write(self.style.WARNING('\nOperation cancelled'))
                return
        
        # Perform the reset
        deleted_counts = {'blacklist': 0, 'exemptions': 0, 'errors': []}
        
        if clear_blacklist:
            # Clear blacklist entries
            try:
                for entry in blacklist_entries:
                    try:
                        blacklist_store.remove_ip(entry['ip_address'])
                        deleted_counts['blacklist'] += 1
                    except Exception as e:
                        deleted_counts['errors'].append(f"Error removing blacklist IP {entry.get('ip_address', 'unknown')}: {e}")
            except Exception as e:
                deleted_counts['errors'].append(f"Error clearing blacklist: {e}")
        
        if clear_exemptions:
            # Clear exemption entries
            try:
                for entry in exemption_entries:
                    try:
                        exemption_store.remove_ip(entry['ip_address'])
                        deleted_counts['exemptions'] += 1
                    except Exception as e:
                        deleted_counts['errors'].append(f"Error removing exemption IP {entry.get('ip_address', 'unknown')}: {e}")
            except Exception as e:
                deleted_counts['errors'].append(f"Error clearing exemptions: {e}")
        
        # Report results
        if deleted_counts['errors']:
            for error in deleted_counts['errors']:
                self.stdout.write(self.style.WARNING(f"⚠️  {error}"))
        
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
        
        if deleted_counts['errors']:
            self.stdout.write(
                self.style.WARNING(f"⚠️  Completed with {len(deleted_counts['errors'])} errors (see above)")
            )
