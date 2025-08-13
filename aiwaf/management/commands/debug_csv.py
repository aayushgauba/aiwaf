from django.core.management.base import BaseCommand
import os
import csv

class Command(BaseCommand):
    help = 'Debug and fix AI-WAF CSV functionality'

    def add_arguments(self, parser):
        parser.add_argument(
            '--test-ip',
            type=str,
            help='Test IP address to add to exemption list',
            default='127.0.0.1'
        )
        parser.add_argument(
            '--fix',
            action='store_true',
            help='Attempt to fix identified issues',
        )

    def handle(self, *args, **options):
        self.stdout.write(self.style.HTTP_INFO("🔍 AI-WAF CSV Debug & Fix"))
        self.stdout.write("")
        
        # Check storage mode
        from django.conf import settings
        storage_mode = getattr(settings, 'AIWAF_STORAGE_MODE', 'models')
        csv_dir = getattr(settings, 'AIWAF_CSV_DATA_DIR', 'aiwaf_data')
        
        self.stdout.write(f"Storage Mode: {storage_mode}")
        self.stdout.write(f"CSV Directory: {csv_dir}")
        self.stdout.write("")
        
        # Check middleware logging
        middleware_logging = getattr(settings, 'AIWAF_MIDDLEWARE_LOGGING', False)
        middleware_log = getattr(settings, 'AIWAF_MIDDLEWARE_LOG', 'aiwaf_requests.log')
        
        self.stdout.write(f"Middleware Logging: {middleware_logging}")
        self.stdout.write(f"Middleware Log File: {middleware_log}")
        self.stdout.write("")
        
        # Check if CSV directory exists
        if os.path.exists(csv_dir):
            self.stdout.write(self.style.SUCCESS(f"✅ CSV directory exists: {csv_dir}"))
        else:
            self.stdout.write(self.style.ERROR(f"❌ CSV directory missing: {csv_dir}"))
            if options['fix']:
                os.makedirs(csv_dir, exist_ok=True)
                self.stdout.write(self.style.SUCCESS(f"✅ Created CSV directory: {csv_dir}"))
        
        # Check CSV files
        csv_files = ['blacklist.csv', 'exemptions.csv', 'keywords.csv']
        for filename in csv_files:
            filepath = os.path.join(csv_dir, filename)
            if os.path.exists(filepath):
                # Count entries
                try:
                    with open(filepath, 'r', newline='', encoding='utf-8') as f:
                        reader = csv.reader(f)
                        rows = list(reader)
                        entry_count = len(rows) - 1 if rows else 0  # Subtract header
                        self.stdout.write(self.style.SUCCESS(f"✅ {filename}: {entry_count} entries"))
                except Exception as e:
                    self.stdout.write(self.style.ERROR(f"❌ {filename}: Error reading - {e}"))
            else:
                self.stdout.write(self.style.WARNING(f"⚠️  {filename}: Not found"))
        
        self.stdout.write("")
        
        # Test storage functionality
        self.stdout.write(self.style.HTTP_INFO("🧪 Testing Storage Functions"))
        
        try:
            from aiwaf.storage import get_exemption_store, get_blacklist_store, get_keyword_store
            
            # Test exemption store
            exemption_store = get_exemption_store()
            self.stdout.write(f"Exemption Store: {exemption_store.__name__}")
            
            # Test blacklist store
            blacklist_store = get_blacklist_store()
            self.stdout.write(f"Blacklist Store: {blacklist_store.__name__}")
            
            # Test keyword store
            keyword_store = get_keyword_store()
            self.stdout.write(f"Keyword Store: {keyword_store.__name__}")
            
        except Exception as e:
            self.stdout.write(self.style.ERROR(f"❌ Storage import failed: {e}"))
            return
        
        self.stdout.write("")
        
        # Test exemption functionality
        test_ip = options['test_ip']
        self.stdout.write(f"🧪 Testing exemption with IP: {test_ip}")
        
        try:
            # Check if already exempted
            is_exempted_before = exemption_store.is_exempted(test_ip)
            self.stdout.write(f"Before: IP {test_ip} exempted = {is_exempted_before}")
            
            # Add to exemption
            exemption_store.add_exemption(test_ip, "Test exemption from debug command")
            self.stdout.write(f"✅ Added {test_ip} to exemption list")
            
            # Check if now exempted
            is_exempted_after = exemption_store.is_exempted(test_ip)
            self.stdout.write(f"After: IP {test_ip} exempted = {is_exempted_after}")
            
            if is_exempted_after:
                self.stdout.write(self.style.SUCCESS("✅ Exemption functionality working!"))
            else:
                self.stdout.write(self.style.ERROR("❌ Exemption functionality not working!"))
                
            # List all exemptions
            all_exemptions = exemption_store.get_all()
            self.stdout.write(f"Total exemptions: {len(all_exemptions)}")
            
            for exemption in all_exemptions:
                self.stdout.write(f"  - {exemption.get('ip_address', exemption)}")
                
        except Exception as e:
            self.stdout.write(self.style.ERROR(f"❌ Exemption test failed: {e}"))
        
        self.stdout.write("")
        
        # Check middleware logger file
        csv_log_file = middleware_log.replace('.log', '.csv')
        if os.path.exists(csv_log_file):
            try:
                with open(csv_log_file, 'r', newline='', encoding='utf-8') as f:
                    reader = csv.reader(f)
                    rows = list(reader)
                    entry_count = len(rows) - 1 if rows else 0
                    self.stdout.write(self.style.SUCCESS(f"✅ Middleware CSV log: {entry_count} entries"))
            except Exception as e:
                self.stdout.write(self.style.ERROR(f"❌ Middleware CSV log error: {e}"))
        else:
            self.stdout.write(self.style.WARNING(f"⚠️  Middleware CSV log not found: {csv_log_file}"))
            self.stdout.write("   Make some requests to generate log entries")
        
        # Recommendations
        self.stdout.write("")
        self.stdout.write(self.style.HTTP_INFO("💡 Recommendations:"))
        
        if storage_mode != 'csv':
            self.stdout.write("1. Set AIWAF_STORAGE_MODE = 'csv' in settings.py")
            
        if not middleware_logging:
            self.stdout.write("2. Set AIWAF_MIDDLEWARE_LOGGING = True in settings.py")
            
        self.stdout.write("3. Add AIWAFLoggerMiddleware to MIDDLEWARE in settings.py")
        self.stdout.write("4. Make some requests to generate log data")
        self.stdout.write("5. Run 'python manage.py detect_and_train' to train with data")
