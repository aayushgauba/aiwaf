#!/usr/bin/env python3

from django.core.management.base import BaseCommand
from django.db import transaction

class Command(BaseCommand):
    help = 'Create Django database migrations for AI-WAF models (after removing CSV support)'

    def handle(self, *args, **options):
        self.stdout.write("🔄 Creating AI-WAF database migrations...")
        
        try:
            # Import the management command functions
            from django.core.management import call_command
            
            # Create migrations for aiwaf app
            self.stdout.write("Creating migrations for aiwaf models...")
            call_command('makemigrations', 'aiwaf', verbosity=2)
            
            # Apply migrations
            self.stdout.write("Applying migrations...")
            call_command('migrate', 'aiwaf', verbosity=2)
            
            self.stdout.write(self.style.SUCCESS("✅ Successfully created and applied AI-WAF migrations!"))
            self.stdout.write("")
            self.stdout.write("🎯 Next steps:")
            self.stdout.write("1. Add your IP to exemptions: python manage.py add_exemption YOUR_IP")
            self.stdout.write("2. Test the system: python manage.py diagnose_blocking --ip YOUR_IP")
            self.stdout.write("3. Clear any old cache: python manage.py clear_cache")
            
        except Exception as e:
            self.stdout.write(self.style.ERROR(f"❌ Error during migration: {e}"))
            self.stdout.write("You may need to run these commands manually:")
            self.stdout.write("  python manage.py makemigrations aiwaf")
            self.stdout.write("  python manage.py migrate aiwaf")
