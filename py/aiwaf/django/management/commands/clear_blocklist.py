from django.core.management.base import BaseCommand
from aiwaf.django.storage import get_blocklist_store

class Command(BaseCommand):
    help = 'Clear all blocklist entries (fast method)'

    def add_arguments(self, parser):
        parser.add_argument(
            '--confirm',
            action='store_true',
            help='Skip confirmation prompt'
        )

    def handle(self, *args, **options):
        confirm = options['confirm']
        
        try:
            blocklist_store = get_blocklist_store()
        except Exception as e:
            self.stdout.write(self.style.ERROR(f'Error initializing blocklist store: {e}'))
            return
        
        # Count current entries safely
        try:
            blocklist_entries = blocklist_store.get_all()
            blocklist_count = len(blocklist_entries)
        except Exception as e:
            self.stdout.write(self.style.WARNING(f'Warning: Could not count blocklist entries: {e}'))
            # Try to get count using clear_all method which returns count
            blocklist_count = "unknown number of"
        
        # Show what will be cleared
        self.stdout.write(f"Clear Blocklist: Will remove {blocklist_count} blocklist entries")
        
        if not confirm:
            try:
                response = input("Are you sure you want to proceed? [y/N]: ")
                if response.lower() not in ['y', 'yes']:
                    self.stdout.write(self.style.WARNING('Operation cancelled'))
                    return
            except (EOFError, KeyboardInterrupt):
                self.stdout.write(self.style.WARNING('\nOperation cancelled'))
                return
        
        # Perform the reset using clear_all for better performance
        try:
            if hasattr(blocklist_store, 'clear_all'):
                deleted_count = blocklist_store.clear_all()
                self.stdout.write(
                    self.style.SUCCESS(f" Blocklist cleared: Deleted {deleted_count} entries")
                )
            else:
                # Fallback to individual deletion
                deleted_count = 0
                for entry in blocklist_entries:
                    try:
                        blocklist_store.remove_ip(entry['ip_address'])
                        deleted_count += 1
                    except Exception as e:
                        self.stdout.write(self.style.WARNING(f"  Error removing IP {entry.get('ip_address', 'unknown')}: {e}"))
                
                self.stdout.write(
                    self.style.SUCCESS(f" Blocklist cleared: Deleted {deleted_count} entries")
                )
        except Exception as e:
            self.stdout.write(self.style.ERROR(f'Error clearing blocklist: {e}'))


# Compatibility aliases for callers using the previous terminology.
get_blacklist_store = get_blocklist_store
