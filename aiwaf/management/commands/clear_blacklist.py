from django.core.management.base import BaseCommand
from aiwaf.storage import get_blacklist_store

class Command(BaseCommand):
    help = 'Clear all blacklist entries (fast method)'

    def add_arguments(self, parser):
        parser.add_argument(
            '--confirm',
            action='store_true',
            help='Skip confirmation prompt'
        )

    def handle(self, *args, **options):
        confirm = options['confirm']
        
        try:
            blacklist_store = get_blacklist_store()
        except Exception as e:
            self.stdout.write(self.style.ERROR(f'Error initializing blacklist store: {e}'))
            return
        
        # Count current entries safely
        try:
            blacklist_entries = blacklist_store.get_all()
            blacklist_count = len(blacklist_entries)
        except Exception as e:
            self.stdout.write(self.style.WARNING(f'Warning: Could not count blacklist entries: {e}'))
            # Try to get count using clear_all method which returns count
            blacklist_count = "unknown number of"
        
        # Show what will be cleared
        self.stdout.write(f"Clear Blacklist: Will remove {blacklist_count} blacklist entries")
        
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
            if hasattr(blacklist_store, 'clear_all'):
                deleted_count = blacklist_store.clear_all()
                self.stdout.write(
                    self.style.SUCCESS(f"✅ Blacklist cleared: Deleted {deleted_count} entries")
                )
            else:
                # Fallback to individual deletion
                deleted_count = 0
                for entry in blacklist_entries:
                    try:
                        blacklist_store.remove_ip(entry['ip_address'])
                        deleted_count += 1
                    except Exception as e:
                        self.stdout.write(self.style.WARNING(f"⚠️  Error removing IP {entry.get('ip_address', 'unknown')}: {e}"))
                
                self.stdout.write(
                    self.style.SUCCESS(f"✅ Blacklist cleared: Deleted {deleted_count} entries")
                )
        except Exception as e:
            self.stdout.write(self.style.ERROR(f'Error clearing blacklist: {e}'))
