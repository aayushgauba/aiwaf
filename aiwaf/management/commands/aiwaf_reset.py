from django.core.management.base import BaseCommand
from aiwaf.storage import get_blacklist_store, get_exemption_store, get_keyword_store
import sys

class Command(BaseCommand):
    help = 'Reset AI-WAF by clearing blacklist, exemption, and/or keyword entries'

    def add_arguments(self, parser):
        parser.add_argument(
            '--blacklist',
            action='store_true',
            help='Clear blacklist entries (default: all)'
        )
        parser.add_argument(
            '--exemptions',
            action='store_true',
            help='Clear exemption entries (default: all)'
        )
        parser.add_argument(
            '--keywords',
            action='store_true',
            help='Clear learned dynamic keywords (default: all)'
        )
        parser.add_argument(
            '--confirm',
            action='store_true',
            help='Skip confirmation prompt'
        )
        
        # Legacy flags for backward compatibility
        parser.add_argument(
            '--blacklist-only',
            action='store_true',
            help='(Legacy) Clear only blacklist entries'
        )
        parser.add_argument(
            '--exemptions-only',
            action='store_true',
            help='(Legacy) Clear only exemption entries'
        )

    def handle(self, *args, **options):
        # Parse arguments
        blacklist_flag = options.get('blacklist', False)
        exemptions_flag = options.get('exemptions', False)
        keywords_flag = options.get('keywords', False)
        confirm = options.get('confirm', False)
        
        # Legacy support
        blacklist_only = options.get('blacklist_only', False)
        exemptions_only = options.get('exemptions_only', False)
        
        # Handle legacy flags
        if blacklist_only:
            blacklist_flag = True
            exemptions_flag = False
            keywords_flag = False
        elif exemptions_only:
            blacklist_flag = False
            exemptions_flag = True
            keywords_flag = False
        
        # If no specific flags, clear everything
        if not (blacklist_flag or exemptions_flag or keywords_flag):
            blacklist_flag = exemptions_flag = keywords_flag = True
        
        try:
            blacklist_store = get_blacklist_store()
            exemption_store = get_exemption_store()
            keyword_store = get_keyword_store()
        except Exception as e:
            self.stdout.write(self.style.ERROR(f'Error initializing stores: {e}'))
            return
        
        # Count current entries safely
        counts = {'blacklist': 0, 'exemptions': 0, 'keywords': 0}
        entries = {'blacklist': [], 'exemptions': [], 'keywords': []}
        
        if blacklist_flag:
            try:
                entries['blacklist'] = blacklist_store.get_all()
                counts['blacklist'] = len(entries['blacklist'])
            except Exception as e:
                self.stdout.write(self.style.WARNING(f'Warning: Could not count blacklist entries: {e}'))
        
        if exemptions_flag:
            try:
                entries['exemptions'] = exemption_store.get_all()
                counts['exemptions'] = len(entries['exemptions'])
            except Exception as e:
                self.stdout.write(self.style.WARNING(f'Warning: Could not count exemption entries: {e}'))
        
        if keywords_flag:
            try:
                entries['keywords'] = keyword_store.get_all_keywords()
                counts['keywords'] = len(entries['keywords'])
            except Exception as e:
                self.stdout.write(self.style.WARNING(f'Warning: Could not count keyword entries: {e}'))
        
        # Build action description
        actions = []
        if blacklist_flag:
            actions.append(f"{counts['blacklist']} blacklist entries")
        if exemptions_flag:
            actions.append(f"{counts['exemptions']} exemption entries")
        if keywords_flag:
            actions.append(f"{counts['keywords']} learned keywords")
        
        action = "Clear " + ", ".join(actions)
        
        # Show what will be cleared
        self.stdout.write(f"🔧 AI-WAF Reset: {action}")
        
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
        deleted_counts = {'blacklist': 0, 'exemptions': 0, 'keywords': 0, 'errors': []}
        
        if blacklist_flag:
            # Clear blacklist entries
            try:
                for entry in entries['blacklist']:
                    try:
                        blacklist_store.remove_ip(entry['ip_address'])
                        deleted_counts['blacklist'] += 1
                    except Exception as e:
                        deleted_counts['errors'].append(f"Error removing blacklist IP {entry.get('ip_address', 'unknown')}: {e}")
            except Exception as e:
                deleted_counts['errors'].append(f"Error clearing blacklist: {e}")
        
        if exemptions_flag:
            # Clear exemption entries
            try:
                for entry in entries['exemptions']:
                    try:
                        exemption_store.remove_ip(entry['ip_address'])
                        deleted_counts['exemptions'] += 1
                    except Exception as e:
                        deleted_counts['errors'].append(f"Error removing exemption IP {entry.get('ip_address', 'unknown')}: {e}")
            except Exception as e:
                deleted_counts['errors'].append(f"Error clearing exemptions: {e}")
        
        if keywords_flag:
            # Clear keyword entries
            try:
                for keyword in entries['keywords']:
                    try:
                        keyword_store.remove_keyword(keyword)
                        deleted_counts['keywords'] += 1
                    except Exception as e:
                        deleted_counts['errors'].append(f"Error removing keyword '{keyword}': {e}")
            except Exception as e:
                deleted_counts['errors'].append(f"Error clearing keywords: {e}")
        
        # Report results
        if deleted_counts['errors']:
            for error in deleted_counts['errors']:
                self.stdout.write(self.style.WARNING(f"⚠️  {error}"))
        
        # Build success message
        success_parts = []
        if blacklist_flag:
            success_parts.append(f"{deleted_counts['blacklist']} blacklist entries")
        if exemptions_flag:
            success_parts.append(f"{deleted_counts['exemptions']} exemption entries")
        if keywords_flag:
            success_parts.append(f"{deleted_counts['keywords']} learned keywords")
        
        success_message = "✅ Reset complete: Deleted " + ", ".join(success_parts)
        self.stdout.write(self.style.SUCCESS(success_message))
        
        if deleted_counts['errors']:
            self.stdout.write(
                self.style.WARNING(f"⚠️  Completed with {len(deleted_counts['errors'])} errors (see above)")
            )
