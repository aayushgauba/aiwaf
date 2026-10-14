from django.core.management.base import BaseCommand
from aiwaf.django.storage import get_blocklist_store, get_exemption_store, get_keyword_store
import sys

class Command(BaseCommand):
    help = 'Reset AI-WAF by clearing blocklist, exemption, and/or keyword entries'

    def add_arguments(self, parser):
        parser.add_argument(
            '--blocklist',
            action='store_true',
            help='Clear blocklist entries (default: all)'
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
            '--blocklist-only',
            action='store_true',
            help='(Legacy) Clear only blocklist entries'
        )
        parser.add_argument(
            '--exemptions-only',
            action='store_true',
            help='(Legacy) Clear only exemption entries'
        )

    def handle(self, *args, **options):
        # Parse arguments
        blocklist_flag = options.get('blocklist', False)
        exemptions_flag = options.get('exemptions', False)
        keywords_flag = options.get('keywords', False)
        confirm = options.get('confirm', False)
        
        # Legacy support
        blocklist_only = options.get('blocklist_only', False)
        exemptions_only = options.get('exemptions_only', False)
        
        # Handle legacy flags
        if blocklist_only:
            blocklist_flag = True
            exemptions_flag = False
            keywords_flag = False
        elif exemptions_only:
            blocklist_flag = False
            exemptions_flag = True
            keywords_flag = False
        
        # If no specific flags, clear everything
        if not (blocklist_flag or exemptions_flag or keywords_flag):
            blocklist_flag = exemptions_flag = keywords_flag = True
        
        try:
            blocklist_store = get_blocklist_store()
            exemption_store = get_exemption_store()
            keyword_store = get_keyword_store()
        except Exception as e:
            self.stdout.write(self.style.ERROR(f'Error initializing stores: {e}'))
            return
        
        # Count current entries safely
        counts = {'blocklist': 0, 'exemptions': 0, 'keywords': 0}
        entries = {'blocklist': [], 'exemptions': [], 'keywords': []}
        
        if blocklist_flag:
            try:
                entries['blocklist'] = blocklist_store.get_all()
                counts['blocklist'] = len(entries['blocklist'])
            except Exception as e:
                self.stdout.write(self.style.WARNING(f'Warning: Could not count blocklist entries: {e}'))
        
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
        if blocklist_flag:
            actions.append(f"{counts['blocklist']} blocklist entries")
        if exemptions_flag:
            actions.append(f"{counts['exemptions']} exemption entries")
        if keywords_flag:
            actions.append(f"{counts['keywords']} learned keywords")
        
        action = "Clear " + ", ".join(actions)
        
        # Show what will be cleared
        self.stdout.write(f" AI-WAF Reset: {action}")
        
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
        deleted_counts = {'blocklist': 0, 'exemptions': 0, 'keywords': 0, 'errors': []}
        
        if blocklist_flag:
            # Clear blocklist entries
            try:
                for entry in entries['blocklist']:
                    try:
                        blocklist_store.remove_ip(entry['ip_address'])
                        deleted_counts['blocklist'] += 1
                    except Exception as e:
                        deleted_counts['errors'].append(f"Error removing blocklist IP {entry.get('ip_address', 'unknown')}: {e}")
            except Exception as e:
                deleted_counts['errors'].append(f"Error clearing blocklist: {e}")
        
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
                self.stdout.write(self.style.WARNING(f"  {error}"))
        
        # Build success message
        success_parts = []
        if blocklist_flag:
            success_parts.append(f"{deleted_counts['blocklist']} blocklist entries")
        if exemptions_flag:
            success_parts.append(f"{deleted_counts['exemptions']} exemption entries")
        if keywords_flag:
            success_parts.append(f"{deleted_counts['keywords']} learned keywords")
        
        success_message = " Reset complete: Deleted " + ", ".join(success_parts)
        self.stdout.write(self.style.SUCCESS(success_message))
        
        if deleted_counts['errors']:
            self.stdout.write(
                self.style.WARNING(f"  Completed with {len(deleted_counts['errors'])} errors (see above)")
            )


# Compatibility aliases for callers using the previous terminology.
get_blacklist_store = get_blocklist_store
