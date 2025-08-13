from django.core.management.base import BaseCommand
import os

class Command(BaseCommand):
    help = 'Test AI-WAF exemption functionality step by step'

    def add_arguments(self, parser):
        parser.add_argument(
            'test_ip',
            type=str,
            help='IP address to test exemption for'
        )

    def handle(self, *args, **options):
        test_ip = options['test_ip']
        
        self.stdout.write(self.style.HTTP_INFO(f"🧪 Testing Exemption for IP: {test_ip}"))
        self.stdout.write("=" * 50)
        
        # Step 1: Check settings
        from django.conf import settings
        storage_mode = getattr(settings, 'AIWAF_STORAGE_MODE', 'models')
        csv_dir = getattr(settings, 'AIWAF_CSV_DATA_DIR', 'aiwaf_data')
        
        self.stdout.write(f"Storage Mode: {storage_mode}")
        self.stdout.write(f"CSV Directory: {csv_dir}")
        self.stdout.write("")
        
        # Step 2: Check storage factory
        try:
            from aiwaf.storage import get_exemption_store, EXEMPTION_CSV, CSV_DATA_DIR, STORAGE_MODE
            exemption_store = get_exemption_store()
            
            self.stdout.write(f"Exemption Store Class: {exemption_store.__name__}")
            self.stdout.write(f"Expected CSV File: {EXEMPTION_CSV}")
            self.stdout.write(f"CSV Directory: {CSV_DATA_DIR}")
            self.stdout.write(f"Storage Mode from storage.py: {STORAGE_MODE}")
            self.stdout.write("")
            
        except Exception as e:
            self.stdout.write(self.style.ERROR(f"❌ Storage import failed: {e}"))
            return
        
        # Step 3: Check file existence
        if os.path.exists(EXEMPTION_CSV):
            self.stdout.write(self.style.SUCCESS(f"✅ Exemption CSV exists: {EXEMPTION_CSV}"))
            
            # Read and display file contents
            try:
                with open(EXEMPTION_CSV, 'r', encoding='utf-8') as f:
                    content = f.read().strip()
                    if content:
                        self.stdout.write(f"📄 File contents:\n{content}")
                        self.stdout.write("")
                    else:
                        self.stdout.write("📄 File is empty")
                        
            except Exception as e:
                self.stdout.write(self.style.ERROR(f"❌ Could not read file: {e}"))
        else:
            self.stdout.write(self.style.ERROR(f"❌ Exemption CSV not found: {EXEMPTION_CSV}"))
            self.stdout.write("Creating test exemption...")
            
            # Create the exemption
            try:
                exemption_store.add_exemption(test_ip, "Test exemption from debug")
                self.stdout.write(self.style.SUCCESS("✅ Created test exemption"))
            except Exception as e:
                self.stdout.write(self.style.ERROR(f"❌ Failed to create exemption: {e}"))
                return
        
        # Step 4: Test exemption check via storage
        try:
            is_exempted_storage = exemption_store.is_exempted(test_ip)
            self.stdout.write(f"Direct storage check: {test_ip} exempted = {is_exempted_storage}")
        except Exception as e:
            self.stdout.write(self.style.ERROR(f"❌ Storage exemption check failed: {e}"))
        
        # Step 5: Test exemption check via utils function
        try:
            from aiwaf.utils import is_ip_exempted
            is_exempted_utils = is_ip_exempted(test_ip)
            self.stdout.write(f"Utils function check: {test_ip} exempted = {is_exempted_utils}")
        except Exception as e:
            self.stdout.write(self.style.ERROR(f"❌ Utils exemption check failed: {e}"))
        
        # Step 6: Test middleware import
        try:
            from aiwaf.middleware import IPAndKeywordBlockMiddleware
            self.stdout.write("✅ Middleware import successful")
        except Exception as e:
            self.stdout.write(self.style.ERROR(f"❌ Middleware import failed: {e}"))
        
        # Step 7: Test CSV reading manually
        if os.path.exists(EXEMPTION_CSV):
            try:
                import csv
                self.stdout.write("\n📋 Manual CSV parsing:")
                with open(EXEMPTION_CSV, 'r', newline='', encoding='utf-8') as f:
                    reader = csv.DictReader(f)
                    found = False
                    for i, row in enumerate(reader):
                        ip_in_row = row.get('ip_address', 'N/A')
                        self.stdout.write(f"  Row {i}: ip_address = '{ip_in_row}'")
                        if ip_in_row == test_ip:
                            found = True
                            self.stdout.write(f"  ✅ Found match for {test_ip}")
                    
                    if not found:
                        self.stdout.write(f"  ❌ No match found for {test_ip}")
                        
            except Exception as e:
                self.stdout.write(self.style.ERROR(f"❌ Manual CSV parsing failed: {e}"))
        
        self.stdout.write("")
        self.stdout.write(self.style.HTTP_INFO("💡 Debugging Tips:"))
        self.stdout.write("1. Check that AIWAF_STORAGE_MODE = 'csv' in settings.py")
        self.stdout.write("2. Ensure the CSV file has proper headers: ip_address,reason,created_at")
        self.stdout.write("3. Check file permissions on the CSV directory")
        self.stdout.write("4. Verify no trailing/leading spaces in IP addresses")
