# aiwaf/middleware_logger.py

import os
import csv
import time
from datetime import datetime
from django.conf import settings
from django.utils.deprecation import MiddlewareMixin
from .utils import get_ip

class AIWAFLoggerMiddleware(MiddlewareMixin):
    """
    Middleware that logs requests to a CSV file for AI-WAF training.
    Acts as a fallback when main access logs are unavailable.
    """
    
    def __init__(self, get_response):
        super().__init__(get_response)
        self.log_file = getattr(settings, "AIWAF_MIDDLEWARE_LOG", "aiwaf_requests.log")
        self.csv_format = getattr(settings, "AIWAF_MIDDLEWARE_CSV", True)
        self.log_enabled = getattr(settings, "AIWAF_MIDDLEWARE_LOGGING", False)
        
        # CSV file path (if using CSV format)
        if self.csv_format and self.log_enabled:
            self.csv_file = self.log_file.replace('.log', '.csv')
            self._ensure_csv_header()
    
    def _ensure_csv_header(self):
        """Ensure CSV file has proper header row"""
        if not os.path.exists(self.csv_file):
            # Create directory if it doesn't exist
            csv_dir = os.path.dirname(self.csv_file)
            if csv_dir and not os.path.exists(csv_dir):
                os.makedirs(csv_dir, exist_ok=True)
            
            with open(self.csv_file, 'w', newline='', encoding='utf-8') as f:
                writer = csv.writer(f)
                writer.writerow([
                    'timestamp', 'ip_address', 'method', 'path', 'status_code', 
                    'response_time', 'user_agent', 'referer', 'content_length'
                ])
    
    def process_request(self, request):
        """Store request start time"""
        request._aiwaf_start_time = time.time()
        return None
    
    def process_response(self, request, response):
        """Log the completed request"""
        if not self.log_enabled:
            return response
            
        # Calculate response time
        start_time = getattr(request, '_aiwaf_start_time', time.time())
        response_time = time.time() - start_time
        
        # Extract request data
        log_data = {
            'timestamp': datetime.now().strftime('%d/%b/%Y:%H:%M:%S +0000'),
            'ip_address': get_ip(request),
            'method': request.method,
            'path': request.path,
            'status_code': response.status_code,
            'response_time': f"{response_time:.3f}",
            'user_agent': request.META.get('HTTP_USER_AGENT', '-'),
            'referer': request.META.get('HTTP_REFERER', '-'),
            'content_length': response.get('Content-Length', '-')
        }
        
        if self.csv_format:
            self._log_to_csv(log_data)
        else:
            self._log_to_text(log_data)
            
        return response
    
    def _log_to_csv(self, data):
        """Write log entry to CSV file"""
        try:
            # Ensure directory exists before writing
            csv_dir = os.path.dirname(self.csv_file)
            if csv_dir and not os.path.exists(csv_dir):
                os.makedirs(csv_dir, exist_ok=True)
                
            with open(self.csv_file, 'a', newline='', encoding='utf-8') as f:
                writer = csv.writer(f)
                writer.writerow([
                    data['timestamp'], data['ip_address'], data['method'],
                    data['path'], data['status_code'], data['response_time'],
                    data['user_agent'], data['referer'], data['content_length']
                ])
        except Exception as e:
            # Fail silently to avoid breaking the application
            pass
    
    def _log_to_text(self, data):
        """Write log entry in common log format"""
        try:
            # Common Log Format with response time
            log_line = f'{data["ip_address"]} - - [{data["timestamp"]}] "{data["method"]} {data["path"]} HTTP/1.1" {data["status_code"]} {data["content_length"]} "{data["referer"]}" "{data["user_agent"]}" response-time={data["response_time"]}\n'
            
            with open(self.log_file, 'a', encoding='utf-8') as f:
                f.write(log_line)
        except Exception as e:
            # Fail silently to avoid breaking the application
            pass


class AIWAFCSVLogParser:
    """
    Parser for AI-WAF CSV logs that converts them to the format expected by trainer.py
    """
    
    @staticmethod
    def parse_csv_log(csv_file_path):
        """
        Parse CSV log file and return records in the format expected by trainer.py
        Returns list of dictionaries with keys: ip, timestamp, path, status, referer, user_agent, response_time
        """
        records = []
        
        if not os.path.exists(csv_file_path):
            return records
        
        try:
            with open(csv_file_path, 'r', newline='', encoding='utf-8') as f:
                reader = csv.DictReader(f)
                for row in reader:
                    try:
                        # Convert timestamp to datetime object
                        timestamp = datetime.strptime(row['timestamp'], '%d/%b/%Y:%H:%M:%S +0000')
                        
                        record = {
                            'ip': row['ip_address'],
                            'timestamp': timestamp,
                            'path': row['path'],
                            'status': row['status_code'],
                            'referer': row['referer'],
                            'user_agent': row['user_agent'],
                            'response_time': float(row['response_time'])
                        }
                        records.append(record)
                    except (ValueError, KeyError) as e:
                        # Skip malformed rows
                        continue
        except Exception as e:
            # Return empty list if file can't be read
            pass
            
        return records
    
    @staticmethod 
    def get_log_lines_for_trainer(csv_file_path):
        """
        Convert CSV log to format compatible with trainer.py's _read_all_logs()
        Returns list of log line strings
        """
        records = AIWAFCSVLogParser.parse_csv_log(csv_file_path)
        log_lines = []
        
        for record in records:
            # Convert back to common log format that trainer.py expects
            timestamp_str = record['timestamp'].strftime('%d/%b/%Y:%H:%M:%S +0000')
            content_length = '-'  # We don't track this in our format
            
            log_line = f'{record["ip"]} - - [{timestamp_str}] "GET {record["path"]} HTTP/1.1" {record["status"]} {content_length} "{record["referer"]}" "{record["user_agent"]}" response-time={record["response_time"]:.3f}'
            log_lines.append(log_line)
            
        return log_lines
