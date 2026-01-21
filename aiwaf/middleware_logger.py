# aiwaf/middleware_logger.py

import time
import os
import csv
import contextlib
from datetime import datetime
from django.conf import settings
from django.utils.deprecation import MiddlewareMixin
from django.utils import timezone
from .utils import get_ip

# Defer model imports to avoid AppRegistryNotReady during Django app loading
RequestLog = None

def _import_models():
    """Import Django models only when needed and apps are ready."""
    global RequestLog
    
    if RequestLog is not None:
        return  # Already imported
    
    try:
        from django.apps import apps
        if apps.ready and apps.is_installed('aiwaf'):
            from .models import RequestLog
    except (ImportError, RuntimeError, Exception):
        # Keep models as None if can't import
        pass

class AIWAFLoggerMiddleware(MiddlewareMixin):
    """
    Middleware that logs requests to Django models for AI-WAF training.
    Acts as a fallback when main access logs are unavailable.
    """
    
    def __init__(self, get_response):
        super().__init__(get_response)
        self.log_enabled = getattr(settings, "AIWAF_MIDDLEWARE_LOGGING", False)
        self.log_file = getattr(settings, "AIWAF_MIDDLEWARE_LOG", "aiwaf_requests.log")
        self.csv_enabled = getattr(settings, "AIWAF_MIDDLEWARE_CSV", True)
        self.log_to_db = getattr(settings, "AIWAF_MIDDLEWARE_DB", True)
    
    def process_request(self, request):
        """Store request start time"""
        request._aiwaf_start_time = time.time()
        return None
    
    def process_response(self, request, response):
        """Log the completed request to Django model"""
        if not self.log_enabled:
            return response
            
        # Calculate response time
        start_time = getattr(request, '_aiwaf_start_time', time.time())
        response_time = time.time() - start_time
        
        if self.csv_enabled:
            self._write_csv_log(request, response, response_time)

        if self.log_to_db:
            _import_models()
            if RequestLog is not None:
                try:
                    RequestLog.objects.create(
                        ip_address=get_ip(request),
                        method=request.method,
                        path=request.path[:500],  # Truncate long paths
                        status_code=response.status_code,
                        response_time=response_time,
                        user_agent=request.META.get('HTTP_USER_AGENT', '')[:2000],  # Truncate long user agents
                        referer=request.META.get('HTTP_REFERER', '')[:500],  # Truncate long referers
                        content_length=response.get('Content-Length', '-'),
                        timestamp=timezone.now()
                    )
                except Exception:
                    # Fail silently to avoid breaking the application
                    pass
            
        return response

    def _write_csv_log(self, request, response, response_time):
        csv_file = self.log_file
        if not csv_file.endswith(".csv"):
            csv_file = csv_file.replace(".log", ".csv")
        log_dir = os.path.dirname(csv_file)
        if log_dir:
            os.makedirs(log_dir, exist_ok=True)

        headers = [
            "timestamp",
            "ip",
            "method",
            "path",
            "status_code",
            "content_length",
            "response_time",
            "referer",
            "user_agent",
        ]
        row = {
            "timestamp": timezone.now().isoformat(),
            "ip": get_ip(request),
            "method": request.method,
            "path": request.path[:500],
            "status_code": response.status_code,
            "content_length": response.get('Content-Length', '-'),
            "response_time": "{:.6f}".format(response_time),
            "referer": request.META.get('HTTP_REFERER', '')[:500],
            "user_agent": request.META.get('HTTP_USER_AGENT', '')[:2000],
        }

        try:
            with _file_lock(csv_file):
                needs_header = not os.path.exists(csv_file) or os.path.getsize(csv_file) == 0
                with open(csv_file, "a", newline="", encoding="utf-8") as f:
                    writer = csv.DictWriter(f, fieldnames=headers)
                    if needs_header:
                        writer.writeheader()
                    writer.writerow(row)
        except Exception:
            # Fail silently to avoid breaking the application
            pass


@contextlib.contextmanager
def _file_lock(target_path):
    """Best-effort cross-platform file lock for concurrent CSV writes."""
    lock_path = target_path + ".lock"
    lock_file = open(lock_path, "a+")
    try:
        if os.name == "nt":
            import msvcrt
            msvcrt.locking(lock_file.fileno(), msvcrt.LK_LOCK, 1)
        else:
            import fcntl
            fcntl.flock(lock_file.fileno(), fcntl.LOCK_EX)
        yield
    finally:
        try:
            if os.name == "nt":
                import msvcrt
                msvcrt.locking(lock_file.fileno(), msvcrt.LK_UNLCK, 1)
            else:
                import fcntl
                fcntl.flock(lock_file.fileno(), fcntl.LOCK_UN)
        finally:
            lock_file.close()


class AIWAFModelLogParser:
    """
    Parser for AI-WAF Django model logs that converts them to the format expected by trainer.py
    """
    
    @staticmethod
    def parse_model_logs():
        """
        Parse Django model logs and return records in the format expected by trainer.py
        Returns list of dictionaries with keys: ip, timestamp, path, status, referer, user_agent, response_time
        """
        records = []
        
        _import_models()
        if RequestLog is None:
            return records
        
        try:
            # Get all request logs
            logs = RequestLog.objects.all().order_by('-timestamp')
            
            for log in logs:
                record = {
                    'ip': str(log.ip_address),
                    'timestamp': log.timestamp,
                    'path': log.path,
                    'status': str(log.status_code),
                    'referer': log.referer if log.referer else '-',
                    'user_agent': log.user_agent if log.user_agent else '-',
                    'response_time': log.response_time
                }
                records.append(record)
        except Exception as e:
            # Return empty list if models can't be accessed
            pass
            
        return records
    
    @staticmethod 
    def get_log_lines_for_trainer():
        """
        Convert Django model logs to format compatible with trainer.py's _read_all_logs()
        Returns list of log line strings
        """
        records = AIWAFModelLogParser.parse_model_logs()
        log_lines = []
        
        for record in records:
            # Convert to common log format that trainer.py expects
            timestamp_str = record['timestamp'].strftime('%d/%b/%Y:%H:%M:%S +0000')
            content_length = '-'  # We don't track this in detail
            
            log_line = f'{record["ip"]} - - [{timestamp_str}] "{record.get("method", "GET")} {record["path"]} HTTP/1.1" {record["status"]} {content_length} "{record["referer"]}" "{record["user_agent"]}" response-time={record["response_time"]:.3f}'
            log_lines.append(log_line)
            
        return log_lines
