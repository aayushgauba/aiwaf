import os
import re
import glob
import gzip
from datetime import datetime
from django.conf import settings
from .storage import get_exemption_store

_LOG_RX = re.compile(
    r'(\d+\.\d+\.\d+\.\d+).*\[(.*?)\].*"(GET|POST) (.*?) HTTP/.*?" (\d{3}).*?"(.*?)" "(.*?)"'
)

def get_ip(request):
    xff = request.META.get("HTTP_X_FORWARDED_FOR", "")
    if xff:
        return xff.split(",")[0].strip()
    return request.META.get("REMOTE_ADDR", "")

def read_rotated_logs(base_path):
    lines = []
    if os.path.exists(base_path):
        with open(base_path, "r", encoding="utf-8", errors="ignore") as f:
            lines.extend(f.readlines())
    for path in sorted(glob.glob(base_path + ".*")):
        opener = gzip.open if path.endswith(".gz") else open
        try:
            with opener(path, "rt", encoding="utf-8", errors="ignore") as f:
                lines.extend(f.readlines())
        except OSError:
            continue
    return lines

def parse_log_line(line):
    m = _LOG_RX.search(line)
    if not m:
        return None
    ip, ts_str, _, path, status, ref, ua = m.groups()
    try:
        ts = datetime.strptime(ts_str.split()[0], "%d/%b/%Y:%H:%M:%S")
    except ValueError:
        return None
    rt_m = re.search(r'response-time=(\d+\.\d+)', line)
    rt = float(rt_m.group(1)) if rt_m else 0.0
    return {
        "ip": ip,
        "timestamp": ts,
        "path": path,
        "status": status,
        "referer": ref,
        "user_agent": ua,
        "response_time": rt
    }

def is_ip_exempted(ip):
    """Check if IP is in exemption list"""
    store = get_exemption_store()
    return store.is_exempted(ip)

def is_view_exempt(request):
    """Check if the current view is marked as AI-WAF exempt"""
    if hasattr(request, 'resolver_match') and request.resolver_match:
        view_func = request.resolver_match.func
        
        # Check if view function has aiwaf_exempt attribute
        if hasattr(view_func, 'aiwaf_exempt'):
            return True
            
        # For class-based views, check the view class
        if hasattr(view_func, 'view_class'):
            view_class = view_func.view_class
            if hasattr(view_class, 'aiwaf_exempt'):
                return True
                
            # Check dispatch method for method_decorator usage
            dispatch_method = getattr(view_class, 'dispatch', None)
            if dispatch_method and hasattr(dispatch_method, 'aiwaf_exempt'):
                return True
                
    return False

def is_exempt_path(path):
    """Check if path should be exempt from AI-WAF"""
    path = path.lower()
    
    # Default login paths (always exempt)
    default_exempt = [
        "/admin/login/", "/admin/", "/login/", "/accounts/login/", 
        "/auth/login/", "/signin/"
    ]
    
    # Check default exempt paths
    for exempt_path in default_exempt:
        if path.startswith(exempt_path):
            return True
        
    # Check configured exempt paths
    exempt_paths = getattr(settings, "AIWAF_EXEMPT_PATHS", [])
    for exempt_path in exempt_paths:
        if path == exempt_path or path.startswith(exempt_path.rstrip("/") + "/"):
            return True
    
    return False

def is_exempt(request):
    """Check if request should be exempt (either by path or view decorator)"""
    return is_exempt_path(request.path) or is_view_exempt(request)