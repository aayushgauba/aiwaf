from django.core.management.base import BaseCommand
from django.conf import settings
import os

class Command(BaseCommand):
    help = 'Manage AI-WAF middleware logging settings and view log status'

    def add_arguments(self, parser):
        parser.add_argument(
            '--enable',
            action='store_true',
            help='Enable middleware logging (shows settings to add)'
        )
        parser.add_argument(
            '--disable',
            action='store_true',
            help='Disable middleware logging (shows settings to remove)'
        )
        parser.add_argument(
            '--status',
            action='store_true',
            help='Show current middleware logging status'
        )
        parser.add_argument(
            '--clear',
            action='store_true',
            help='Clear/delete middleware log files'
        )

    def handle(self, *args, **options):
        if options['enable']:
            self._show_enable_instructions()
        elif options['disable']:
            self._show_disable_instructions()
        elif options['clear']:
            self._clear_logs()
        else:
            self._show_status()

    def _show_status(self):
        """Show current middleware logging configuration"""
        self.stdout.write(self.style.HTTP_INFO("🔍 AI-WAF Middleware Logging Status"))
        self.stdout.write("")
        
        # Check settings
        logging_enabled = getattr(settings, 'AIWAF_MIDDLEWARE_LOGGING', False)
        log_file = getattr(settings, 'AIWAF_MIDDLEWARE_LOG', 'aiwaf_requests.log')
        csv_format = getattr(settings, 'AIWAF_MIDDLEWARE_CSV', True)
        csv_file = log_file.replace('.log', '.csv') if csv_format else None
        
        # Status
        status_color = self.style.SUCCESS if logging_enabled else self.style.WARNING
        self.stdout.write(f"Status: {status_color('ENABLED' if logging_enabled else 'DISABLED')}")
        self.stdout.write(f"Log File: {log_file}")
        if csv_format:
            self.stdout.write(f"CSV File: {csv_file}")
        self.stdout.write(f"Format: {'CSV' if csv_format else 'Text'}")
        self.stdout.write("")
        
        # File existence and sizes
        if logging_enabled:
            self.stdout.write("📁 Log Files:")
            
            if csv_format and csv_file:
                if os.path.exists(csv_file):
                    size = os.path.getsize(csv_file)
                    lines = self._count_csv_lines(csv_file)
                    self.stdout.write(f"  ✅ {csv_file} ({size:,} bytes, {lines:,} entries)")
                else:
                    self.stdout.write(f"  ❌ {csv_file} (not found)")
            
            if os.path.exists(log_file):
                size = os.path.getsize(log_file)
                self.stdout.write(f"  ✅ {log_file} ({size:,} bytes)")
            else:
                self.stdout.write(f"  ❌ {log_file} (not found)")
        
        # Middleware check
        middleware_list = getattr(settings, 'MIDDLEWARE', [])
        middleware_installed = 'aiwaf.middleware_logger.AIWAFLoggerMiddleware' in middleware_list
        
        self.stdout.write("")
        middleware_color = self.style.SUCCESS if middleware_installed else self.style.ERROR
        self.stdout.write(f"Middleware: {middleware_color('INSTALLED' if middleware_installed else 'NOT INSTALLED')}")
        
        if logging_enabled and not middleware_installed:
            self.stdout.write(self.style.WARNING("⚠️  Logging is enabled but middleware is not installed!"))

    def _show_enable_instructions(self):
        """Show instructions for enabling middleware logging"""
        self.stdout.write(self.style.SUCCESS("🚀 Enable AI-WAF Middleware Logging"))
        self.stdout.write("")
        self.stdout.write("Add these settings to your Django settings.py:")
        self.stdout.write("")
        self.stdout.write(self.style.HTTP_INFO("# Enable AI-WAF middleware logging"))
        self.stdout.write(self.style.HTTP_INFO("AIWAF_MIDDLEWARE_LOGGING = True"))
        self.stdout.write(self.style.HTTP_INFO("AIWAF_MIDDLEWARE_LOG = 'aiwaf_requests.log'  # Optional"))
        self.stdout.write(self.style.HTTP_INFO("AIWAF_MIDDLEWARE_CSV = True  # Optional (default: True)"))
        self.stdout.write("")
        self.stdout.write("Add middleware to MIDDLEWARE list (preferably near the end):")
        self.stdout.write("")
        self.stdout.write(self.style.HTTP_INFO("MIDDLEWARE = ["))
        self.stdout.write(self.style.HTTP_INFO("    # ... your existing middleware ..."))
        self.stdout.write(self.style.HTTP_INFO("    'aiwaf.middleware_logger.AIWAFLoggerMiddleware',"))
        self.stdout.write(self.style.HTTP_INFO("]"))
        self.stdout.write("")
        self.stdout.write("Benefits:")
        self.stdout.write("  ✅ Fallback when main access logs unavailable")
        self.stdout.write("  ✅ CSV format for easy analysis") 
        self.stdout.write("  ✅ Automatic integration with AI-WAF trainer")
        self.stdout.write("  ✅ Captures response times for better detection")

    def _show_disable_instructions(self):
        """Show instructions for disabling middleware logging"""
        self.stdout.write(self.style.WARNING("⏹️  Disable AI-WAF Middleware Logging"))
        self.stdout.write("")
        self.stdout.write("To disable, update your Django settings.py:")
        self.stdout.write("")
        self.stdout.write(self.style.HTTP_INFO("# Disable AI-WAF middleware logging"))
        self.stdout.write(self.style.HTTP_INFO("AIWAF_MIDDLEWARE_LOGGING = False"))
        self.stdout.write("")
        self.stdout.write("And remove from MIDDLEWARE list:")
        self.stdout.write("")
        self.stdout.write(self.style.HTTP_INFO("MIDDLEWARE = ["))
        self.stdout.write(self.style.HTTP_INFO("    # ... your existing middleware ..."))
        self.stdout.write(self.style.HTTP_INFO("    # 'aiwaf.middleware_logger.AIWAFLoggerMiddleware',  # Remove this line"))
        self.stdout.write(self.style.HTTP_INFO("]"))

    def _clear_logs(self):
        """Clear/delete middleware log files"""
        log_file = getattr(settings, 'AIWAF_MIDDLEWARE_LOG', 'aiwaf_requests.log')
        csv_format = getattr(settings, 'AIWAF_MIDDLEWARE_CSV', True)
        csv_file = log_file.replace('.log', '.csv') if csv_format else None
        
        files_deleted = 0
        
        # Delete CSV file
        if csv_file and os.path.exists(csv_file):
            try:
                os.remove(csv_file)
                self.stdout.write(self.style.SUCCESS(f"✅ Deleted {csv_file}"))
                files_deleted += 1
            except Exception as e:
                self.stdout.write(self.style.ERROR(f"❌ Failed to delete {csv_file}: {e}"))
        
        # Delete text log file
        if os.path.exists(log_file):
            try:
                os.remove(log_file)
                self.stdout.write(self.style.SUCCESS(f"✅ Deleted {log_file}"))
                files_deleted += 1
            except Exception as e:
                self.stdout.write(self.style.ERROR(f"❌ Failed to delete {log_file}: {e}"))
        
        if files_deleted == 0:
            self.stdout.write(self.style.WARNING("ℹ️  No log files found to delete"))
        else:
            self.stdout.write(self.style.SUCCESS(f"🗑️  Deleted {files_deleted} log file(s)"))

    def _count_csv_lines(self, csv_file):
        """Count lines in CSV file (excluding header)"""
        try:
            with open(csv_file, 'r', encoding='utf-8') as f:
                return sum(1 for line in f) - 1  # Subtract header
        except:
            return 0
