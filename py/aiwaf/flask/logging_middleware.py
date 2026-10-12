"""
AIWAF Logging Middleware

Logs all requests in Gunicorn/Nginx style format for analysis.
Creates standard web server access logs with AIWAF security annotations.
"""

import csv
import os
import logging
from datetime import datetime
from pathlib import Path
from flask import request, g
from .exemption_decorators import should_apply_middleware
import time
from aiwaf.core.request_context import extract_logging_context_from_flask_request

logger = logging.getLogger(__name__)


class AIWAFLoggingMiddleware:
    """Middleware to log requests in standard web server format."""
    
    def __init__(self, app=None, log_dir=None):
        self.app = app
        self.log_dir = log_dir or 'aiwaf_logs'
        
        if app is not None:
            self.init_app(app)
    
    def init_app(self, app):
        """Initialize the middleware with the Flask app."""
        self.app = app
        
        # Get log directory from config or use default
        self.log_dir = app.config.get('AIWAF_LOG_DIR', self.log_dir)
        
        # Create log directory if it doesn't exist
        Path(self.log_dir).mkdir(exist_ok=True)
        
        # Register middleware
        app.before_request(self.before_request)
        app.after_request(self.after_request)
        
        # Set up file paths - using standard web server log names
        self.access_log_file = Path(self.log_dir) / 'access.log'
        self.error_log_file = Path(self.log_dir) / 'error.log'
        self.aiwaf_log_file = Path(self.log_dir) / 'aiwaf.log'
        
        # Log format options
        self.log_format = app.config.get('AIWAF_LOG_FORMAT', 'combined')  # 'combined', 'common', 'json', 'csv'
    
    def before_request(self):
        """Record request start time."""
        # Check exemption status first - skip logging if exempt
        if not should_apply_middleware('logging'):
            return None  # Skip logging for this request
        
        g.aiwaf_start_time = time.time()
        g.aiwaf_blocked = False
        g.aiwaf_block_reason = None

    def close(self):
        """Release the native writer handle after request processing has stopped."""
        from aiwaf.core.native_runtime import close_csv_logs
        close_csv_logs(str(self.access_log_file))
    
    def after_request(self, response):
        """Log request in web server format after processing."""
        try:
            self._log_access(response)
            
            # Log errors separately
            if response.status_code >= 400:
                self._log_error(response)
                
            # Log AIWAF specific events
            if getattr(g, 'aiwaf_blocked', False):
                self._log_aiwaf_event(response)
                
        except Exception as e:
            # Don't let logging errors break the application
            logger.exception(f"AIWAF Logging Error: {e}")
        
        return response
    
    def _log_access(self, response):
        """Log access in standard web server format."""
        if self.log_format == 'csv':
            if not self.app.config.get('AIWAF_USE_CSV', True):
                self._log_access_combined(response)
            else:
                self._log_access_csv(response)
        elif self.log_format == 'json':
            self._log_access_json(response)
        else:
            self._log_access_combined(response)
    
    def _log_access_combined(self, response):
        """Log in Apache/Nginx Combined Log Format."""
        # Combined Log Format:
        # %h %l %u %t "%r" %>s %O "%{Referer}i" "%{User-Agent}i"
        
        start_time = getattr(g, 'aiwaf_start_time', time.time())
        response_time_ms = int((time.time() - start_time) * 1000)
        
        ip = self._get_client_ip()
        ctx = extract_logging_context_from_flask_request(request, ip=ip)
        # Use a timezone-safe timestamp format for cross-platform compatibility
        now = datetime.now()
        timestamp = now.strftime('[%d/%b/%Y:%H:%M:%S +0000]')
        method = ctx["method"]
        path = ctx["path_with_query"]
        protocol = ctx["protocol"]
        status_code = response.status_code
        content_length = response.content_length or '-'
        referer = ctx["referer"] or '-'
        user_agent = ctx["user_agent"] or '-'
        
        # Add AIWAF specific fields
        blocked = 'BLOCKED' if getattr(g, 'aiwaf_blocked', False) else '-'
        block_reason = getattr(g, 'aiwaf_block_reason', '-')
        
        # Standard combined format with AIWAF extensions
        if self.log_format == 'combined':
            log_line = (
                f'{ip} - - {timestamp} "{method} {path} {protocol}" '
                f'{status_code} {content_length} "{referer}" "{user_agent}" '
                f'{response_time_ms}ms {blocked} "{block_reason}"'
            )
        else:  # common format
            log_line = (
                f'{ip} - - {timestamp} "{method} {path} {protocol}" '
                f'{status_code} {content_length}'
            )
        
        with open(self.access_log_file, 'a', encoding='utf-8') as f:
            f.write(log_line + '\n')
    
    def _log_access_csv(self, response):
        """Log access in CSV format for easy analysis."""
        start_time = getattr(g, 'aiwaf_start_time', time.time())
        response_time_ms = int((time.time() - start_time) * 1000)
        
        headers = [
            'timestamp', 'ip', 'method', 'path', 'query_string', 'protocol',
            'status_code', 'content_length', 'response_time_ms', 'referer',
            'user_agent', 'blocked', 'block_reason'
        ]

        row = {
            'timestamp': datetime.now().isoformat(),
            **extract_logging_context_from_flask_request(request, ip=self._get_client_ip()),
            'status_code': response.status_code,
            'content_length': response.content_length or 0,
            'response_time_ms': response_time_ms,
            'blocked': getattr(g, 'aiwaf_blocked', False),
            'block_reason': getattr(g, 'aiwaf_block_reason', ''),
        }
        row.pop("path_with_query", None)

        from aiwaf.core.native_runtime import csv_function, csv_values
        native_log = csv_function('csv_log_append')
        if native_log is not None:
            native_log(str(self.access_log_file), headers,
                       csv_values([row.get(key, '') for key in headers]),
                       bool(self.app.config.get('AIWAF_CSV_LOG_FSYNC', False)))
            return
        native = csv_function('csv_write')
        if native is not None:
            native(str(self.access_log_file), headers,
                   [csv_values([row.get(key, '') for key in headers])], True)
            return

        # Python fallback
        if not self.access_log_file.exists():
            with open(self.access_log_file, 'w', newline='', encoding='utf-8') as f:
                writer = csv.writer(f)
                writer.writerow(headers)

        with open(self.access_log_file, 'a', newline='', encoding='utf-8') as f:
            writer = csv.writer(f)
            writer.writerow([row.get(key, '') for key in headers])
    
    def _log_access_json(self, response):
        """Log access in JSON format."""
        import json
        
        start_time = getattr(g, 'aiwaf_start_time', time.time())
        response_time_ms = int((time.time() - start_time) * 1000)
        
        log_data = {
            'timestamp': datetime.now().isoformat(),
            **extract_logging_context_from_flask_request(request, ip=self._get_client_ip()),
            'status_code': response.status_code,
            'content_length': response.content_length or 0,
            'response_time_ms': response_time_ms,
            'blocked': getattr(g, 'aiwaf_blocked', False),
            'block_reason': getattr(g, 'aiwaf_block_reason', '')
        }
        log_data.pop("path_with_query", None)
        
        with open(self.access_log_file, 'a', encoding='utf-8') as f:
            f.write(json.dumps(log_data) + '\n')
    
    def _log_error(self, response):
        """Log errors in standard error log format."""
        timestamp = datetime.now().strftime('[%Y-%m-%d %H:%M:%S]')
        ctx = extract_logging_context_from_flask_request(request, ip=self._get_client_ip())
        status_code = response.status_code
        user_agent = ctx["user_agent"] or '-'
        
        error_line = (
            f'{timestamp} [error] {status_code} from {ctx["ip"]}: '
            f'{ctx["method"]} {ctx["path"]} "{user_agent}"'
        )
        
        with open(self.error_log_file, 'a', encoding='utf-8') as f:
            f.write(error_line + '\n')
    
    def _log_aiwaf_event(self, response):
        """Log AIWAF specific security events."""
        timestamp = datetime.now().strftime('[%Y-%m-%d %H:%M:%S]')
        ctx = extract_logging_context_from_flask_request(request, ip=self._get_client_ip())
        block_reason = getattr(g, 'aiwaf_block_reason', 'unknown')
        user_agent = ctx["user_agent"] or '-'
        
        aiwaf_line = (
            f'{timestamp} [AIWAF] BLOCKED {ctx["ip"]} - {block_reason} - '
            f'{ctx["method"]} {ctx["path"]} "{user_agent}"'
        )
        
        with open(self.aiwaf_log_file, 'a', encoding='utf-8') as f:
            f.write(aiwaf_line + '\n')
    
    def mark_request_blocked(self, reason):
        """Mark current request as blocked with reason."""
        g.aiwaf_blocked = True
        g.aiwaf_block_reason = reason
    
    def _get_client_ip(self):
        """Get the real client IP address."""
        if not request:
            return 'unknown'
        
        # Check for forwarded headers (common in reverse proxy setups)
        if 'X-Forwarded-For' in request.headers:
            return request.headers['X-Forwarded-For'].split(',')[0].strip()
        elif 'X-Real-IP' in request.headers:
            return request.headers['X-Real-IP']
        elif 'CF-Connecting-IP' in request.headers:  # Cloudflare
            return request.headers['CF-Connecting-IP']
        else:
            return request.remote_addr or 'unknown'


def get_logging_middleware():
    """Factory function to get the logging middleware instance."""
    return AIWAFLoggingMiddleware()


# Utility functions for log analysis (Gunicorn/Nginx style)
def analyze_access_logs(log_dir='aiwaf_logs', log_format='combined'):
    """Analyze access logs in standard web server format."""
    log_path = Path(log_dir)
    access_log = log_path / 'access.log'
    
    if not access_log.exists():
        return {"error": "Access log not found"}
    
    stats = {
        'total_requests': 0,
        'blocked_requests': 0,
        'status_codes': {},
        'ips': {},
        'paths': {},
        'user_agents': {},
        'methods': {},
        'hourly_distribution': {},
        'response_times': [],
        'blocked_reasons': {}
    }
    
    try:
        if log_format == 'csv':
            _analyze_csv_logs(access_log, stats)
        elif log_format == 'json':
            _analyze_json_logs(access_log, stats)
        else:
            _analyze_combined_logs(access_log, stats)
            
    except Exception as e:
        return {"error": f"Error analyzing logs: {e}"}
    
    # Calculate averages and percentiles
    if stats['response_times']:
        stats['avg_response_time'] = sum(stats['response_times']) / len(stats['response_times'])
        stats['response_times'].sort()
        stats['p95_response_time'] = stats['response_times'][int(0.95 * len(stats['response_times']))]
    
    # Get top items
    stats['top_ips'] = sorted(stats['ips'].items(), key=lambda x: x[1], reverse=True)[:10]
    stats['top_paths'] = sorted(stats['paths'].items(), key=lambda x: x[1], reverse=True)[:10]
    stats['top_user_agents'] = sorted(stats['user_agents'].items(), key=lambda x: x[1], reverse=True)[:5]
    
    return stats


def _analyze_csv_logs(log_file, stats):
    """Analyze CSV format logs."""
    with open(log_file, 'r', encoding='utf-8') as f:
        reader = csv.DictReader(f)
        for row in reader:
            stats['total_requests'] += 1
            
            # Track status codes
            status = row.get('status_code', '0')
            stats['status_codes'][status] = stats['status_codes'].get(status, 0) + 1
            
            # Track IPs
            ip = row.get('ip', 'unknown')
            stats['ips'][ip] = stats['ips'].get(ip, 0) + 1
            
            # Track paths
            path = row.get('path', 'unknown')
            stats['paths'][path] = stats['paths'].get(path, 0) + 1
            
            # Track methods
            method = row.get('method', 'unknown')
            stats['methods'][method] = stats['methods'].get(method, 0) + 1
            
            # Track blocked requests
            if row.get('blocked', '').lower() == 'true':
                stats['blocked_requests'] += 1
                reason = row.get('block_reason', 'unknown')
                stats['blocked_reasons'][reason] = stats['blocked_reasons'].get(reason, 0) + 1
            
            # Track response times
            try:
                response_time = int(row.get('response_time_ms', 0))
                stats['response_times'].append(response_time)
            except:
                pass
            
            # Track hourly distribution
            try:
                timestamp = row.get('timestamp', '')
                hour = timestamp.split('T')[1].split(':')[0] if 'T' in timestamp else '00'
                stats['hourly_distribution'][hour] = stats['hourly_distribution'].get(hour, 0) + 1
            except:
                pass


def _analyze_json_logs(log_file, stats):
    """Analyze JSON format logs."""
    import json
    
    with open(log_file, 'r', encoding='utf-8') as f:
        for line in f:
            try:
                row = json.loads(line.strip())
                stats['total_requests'] += 1
                
                # Similar analysis as CSV but with JSON structure
                status = str(row.get('status_code', 0))
                stats['status_codes'][status] = stats['status_codes'].get(status, 0) + 1
                
                ip = row.get('ip', 'unknown')
                stats['ips'][ip] = stats['ips'].get(ip, 0) + 1
                
                if row.get('blocked', False):
                    stats['blocked_requests'] += 1
                    reason = row.get('block_reason', 'unknown')
                    stats['blocked_reasons'][reason] = stats['blocked_reasons'].get(reason, 0) + 1
                
                # Response times
                response_time = row.get('response_time_ms', 0)
                if response_time:
                    stats['response_times'].append(response_time)
                    
            except json.JSONDecodeError:
                continue


def _analyze_combined_logs(log_file, stats):
    """Analyze Combined/Common log format."""
    import re
    
    # Combined log format regex
    log_pattern = re.compile(
        r'(?P<ip>\S+) \S+ \S+ \[(?P<timestamp>[^\]]+)\] "(?P<method>\S+) (?P<path>\S+) (?P<protocol>\S+)" '
        r'(?P<status>\d+) (?P<size>\S+) "(?P<referer>[^"]*)" "(?P<user_agent>[^"]*)"'
        r'(?:\s+(?P<response_time>\d+)ms)?(?:\s+(?P<blocked>\S+))?(?:\s+"(?P<block_reason>[^"]*)")?'
    )
    
    with open(log_file, 'r', encoding='utf-8') as f:
        for line in f:
            match = log_pattern.match(line.strip())
            if match:
                stats['total_requests'] += 1
                data = match.groupdict()
                
                # Track statistics
                status = data.get('status', '0')
                stats['status_codes'][status] = stats['status_codes'].get(status, 0) + 1
                
                ip = data.get('ip', 'unknown')
                stats['ips'][ip] = stats['ips'].get(ip, 0) + 1
                
                path = data.get('path', 'unknown')
                stats['paths'][path] = stats['paths'].get(path, 0) + 1
                
                if data.get('blocked') == 'BLOCKED':
                    stats['blocked_requests'] += 1
                    reason = data.get('block_reason', 'unknown')
                    stats['blocked_reasons'][reason] = stats['blocked_reasons'].get(reason, 0) + 1
