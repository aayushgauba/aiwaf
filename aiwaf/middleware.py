# aiwaf/middleware.py

import time
import re
import os
import warnings
import numpy as np
import joblib
from django.db.models import UUIDField
from collections import defaultdict
from django.utils.deprecation import MiddlewareMixin
from django.http import JsonResponse
from django.conf import settings
from django.core.cache import cache
from django.db.models import F
from django.apps import apps
from django.urls import get_resolver
from .trainer import STATIC_KW, STATUS_IDX, path_exists_in_django
from .blacklist_manager import BlacklistManager
from .models import IPExemption
from .utils import is_exempt, get_ip, is_ip_exempted, is_exempt_path
from .storage import get_keyword_store

MODEL_PATH = getattr(
    settings,
    "AIWAF_MODEL_PATH",
    os.path.join(os.path.dirname(__file__), "resources", "model.pkl")
)

def load_model_safely():
    """Load the AI model with version compatibility checking."""
    import warnings
    import sklearn
    
    try:
        # Suppress sklearn version warnings temporarily
        with warnings.catch_warnings():
            warnings.filterwarnings("ignore", category=UserWarning, module="sklearn.base")
            model_data = joblib.load(MODEL_PATH)
            
            # Handle both old format (direct model) and new format (with metadata)
            if isinstance(model_data, dict) and 'model' in model_data:
                # New format with metadata
                model = model_data['model']
                stored_version = model_data.get('sklearn_version', 'unknown')
                current_version = sklearn.__version__
                
                if stored_version != current_version:
                    print(f"ℹ️  Model was trained with sklearn v{stored_version}, current v{current_version}")
                    print("   Run 'python manage.py detect_and_train' to update model if needed.")
                
                return model
            else:
                # Old format - direct model object
                print("ℹ️  Using legacy model format. Consider retraining for better compatibility.")
                return model_data
                
    except Exception as e:
        print(f"Warning: Could not load AI model from {MODEL_PATH}: {e}")
        print("AI anomaly detection will be disabled until model is retrained.")
        print("Run 'python manage.py detect_and_train' to regenerate the model.")
        return None

# Load model with safety checks
MODEL = load_model_safely()

STATIC_KW = getattr(
    settings,
    "AIWAF_MALICIOUS_KEYWORDS",
    [
        ".php", "xmlrpc", "wp-", ".env", ".git", ".bak",
        "conflg", "shell", "filemanager"
    ]
)

def get_ip(request):
    xff = request.META.get("HTTP_X_FORWARDED_FOR")
    if xff:
        return xff.split(",")[0].strip()
    return request.META.get("REMOTE_ADDR", "")

class IPAndKeywordBlockMiddleware:
    def __init__(self, get_response):
        self.get_response = get_response
        self.safe_prefixes = self._collect_safe_prefixes()
        self.exempt_keywords = self._get_exempt_keywords()
        self.legitimate_path_keywords = self._get_legitimate_path_keywords()

    def _get_exempt_keywords(self):
        """Get keywords that should be exempt from blocking"""
        exempt_tokens = set()
        
        # Extract from exempt paths
        for path in getattr(settings, "AIWAF_EXEMPT_PATHS", []):
            for seg in re.split(r"\W+", path.strip("/").lower()):
                if len(seg) > 3:
                    exempt_tokens.add(seg)
        
        # Add explicit exempt keywords from settings
        exempt_keywords = getattr(settings, "AIWAF_EXEMPT_KEYWORDS", [])
        exempt_tokens.update(exempt_keywords)
        
        return exempt_tokens

    def _get_legitimate_path_keywords(self):
        """Get keywords that are legitimate in URL paths - uses same logic as trainer"""
        # Import the enhanced function from trainer to ensure consistency
        try:
            from .trainer import get_legitimate_keywords
            return get_legitimate_keywords()
        except ImportError:
            # Fallback to local implementation if trainer import fails
            return self._get_legitimate_keywords_fallback()
    
    def _get_legitimate_keywords_fallback(self):
        """Fallback implementation matching trainer.py logic"""
        legitimate = set()
        
        # Common legitimate path segments - matches trainer.py
        default_legitimate = {
            "profile", "user", "users", "account", "accounts", "settings", "dashboard", 
            "home", "about", "contact", "help", "search", "list", "lists",
            "view", "views", "edit", "create", "update", "delete", "detail", "details",
            "api", "auth", "login", "logout", "register", "signup", "signin",
            "reset", "confirm", "activate", "verify", "page", "pages",
            "category", "categories", "tag", "tags", "post", "posts",
            "article", "articles", "blog", "blogs", "news", "item", "items",
            "admin", "administration", "manage", "manager", "control", "panel",
            "config", "configuration", "option", "options", "preference", "preferences"
        }
        legitimate.update(default_legitimate)
        
        # Extract keywords from Django URL patterns and app names - matches trainer.py
        legitimate.update(self._extract_django_route_keywords())
        
        # Add from Django settings
        allowed_path_keywords = getattr(settings, "AIWAF_ALLOWED_PATH_KEYWORDS", [])
        legitimate.update(allowed_path_keywords)
        
        # Add exempt keywords
        exempt_keywords = getattr(settings, "AIWAF_EXEMPT_KEYWORDS", [])
        legitimate.update(exempt_keywords)
        
        return legitimate

    def _extract_django_route_keywords(self):
        """Extract legitimate keywords from Django URL patterns, app names, and model names - matches trainer.py"""
        keywords = set()
        
        try:
            from django.urls.resolvers import URLResolver, URLPattern
            
            # Extract from app names and labels
            for app_config in apps.get_app_configs():
                # Add app name and label
                if app_config.name:
                    for segment in re.split(r'[._-]', app_config.name.lower()):
                        if len(segment) > 2:
                            keywords.add(segment)
                
                if app_config.label and app_config.label != app_config.name:
                    for segment in re.split(r'[._-]', app_config.label.lower()):
                        if len(segment) > 2:
                            keywords.add(segment)
                
                # Extract from model names in the app
                try:
                    for model in app_config.get_models():
                        model_name = model._meta.model_name.lower()
                        if len(model_name) > 2:
                            keywords.add(model_name)
                        # Add plural form
                        if not model_name.endswith('s'):
                            keywords.add(f"{model_name}s")
                except Exception:
                    continue
            
            # Extract from URL patterns
            def extract_from_pattern(pattern, prefix=""):
                try:
                    if isinstance(pattern, URLResolver):
                        # Handle include() patterns
                        namespace = getattr(pattern, 'namespace', None)
                        if namespace:
                            for segment in re.split(r'[._-]', namespace.lower()):
                                if len(segment) > 2:
                                    keywords.add(segment)
                        
                        # Extract from the pattern itself
                        pattern_str = str(pattern.pattern)
                        for segment in re.findall(r'([a-zA-Z]\w{2,})', pattern_str):
                            keywords.add(segment.lower())
                        
                        # Recurse into nested patterns
                        for nested_pattern in pattern.url_patterns:
                            extract_from_pattern(nested_pattern, prefix)
                    
                    elif isinstance(pattern, URLPattern):
                        # Extract from URL pattern
                        pattern_str = str(pattern.pattern)
                        for segment in re.findall(r'([a-zA-Z]\w{2,})', pattern_str):
                            keywords.add(segment.lower())
                        
                        # Extract from view name if available
                        if hasattr(pattern.callback, '__name__'):
                            view_name = pattern.callback.__name__.lower()
                            for segment in re.split(r'[._-]', view_name):
                                if len(segment) > 2 and segment != 'view':
                                    keywords.add(segment)
                
                except Exception:
                    pass
            
            # Process all URL patterns
            root_resolver = get_resolver()
            for pattern in root_resolver.url_patterns:
                extract_from_pattern(pattern)
                
        except Exception as e:
            # Silently continue if extraction fails
            pass
        
        # Filter out very common/generic words that might be suspicious
        filtered_keywords = set()
        for keyword in keywords:
            if (len(keyword) >= 3 and 
                keyword not in ['www', 'com', 'org', 'net', 'int', 'str', 'obj', 'get', 'set', 'put', 'del']):
                filtered_keywords.add(keyword)
        
        return filtered_keywords

    def _is_malicious_context(self, request, segment):
        """Determine if a keyword appears in a malicious context"""
        path = request.path.lower()
        
        # Check if this is a query parameter attack
        query_string = request.META.get('QUERY_STRING', '').lower()
        if segment in query_string and any(attack_pattern in query_string for attack_pattern in [
            'union', 'select', 'drop', 'insert', 'script', 'alert', 'eval'
        ]):
            return True
        
        # Check if this looks like a file extension attack
        if segment.startswith('.') and not path_exists_in_django(request.path):
            return True
        
        # Check if this looks like a directory traversal
        if '../' in path or '..\\' in path:
            return True
        
        # Check if accessing non-existent paths with suspicious extensions
        if (not path_exists_in_django(request.path) and 
            any(ext in segment for ext in ['.php', '.asp', '.jsp', '.cgi'])):
            return True
        
        return False

    def _collect_safe_prefixes(self):
        resolver = get_resolver()
        prefixes = set()

        def extract(patterns_list, prefix=""):
            for p in patterns_list:
                if hasattr(p, "url_patterns"):  # include()
                    full_prefix = (prefix + str(p.pattern)).strip("^/").split("/")[0]
                    prefixes.add(full_prefix)
                    extract(p.url_patterns, prefix + str(p.pattern))
                else:
                    pat = (prefix + str(p.pattern)).strip("^$")
                    path_parts = pat.strip("/").split("/")
                    if path_parts:
                        prefixes.add(path_parts[0])
        extract(resolver.url_patterns)
        return prefixes

    def __call__(self, request):
        # First exemption check - early exit for exempt requests
        if is_exempt(request):
            return self.get_response(request)
            
        raw_path = request.path.lower()
        ip = get_ip(request)
        path = raw_path.lstrip("/")
        
        # Additional IP-level exemption check
        from .storage import get_exemption_store
        exemption_store = get_exemption_store()
        if exemption_store.is_exempted(ip):
            return self.get_response(request)
        
        # BlacklistManager handles exemption checking internally
        if BlacklistManager.is_blocked(ip):
            return JsonResponse({"error": "blocked"}, status=403)
        
        # Check if path exists in Django - if yes, be more lenient
        path_exists = path_exists_in_django(request.path)
        
        keyword_store = get_keyword_store()
        segments = [seg for seg in re.split(r"\W+", path) if len(seg) > 3]
        
        # Only learn keywords from non-existent paths or suspicious contexts
        for seg in segments:
            if not path_exists or self._is_malicious_context(request, seg):
                keyword_store.add_keyword(seg)
            
        dynamic_top = keyword_store.get_top_keywords(getattr(settings, "AIWAF_DYNAMIC_TOP_N", 10))
        all_kw = set(STATIC_KW) | set(dynamic_top)
        
        # Enhanced filtering logic
        suspicious_kw = set()
        for kw in all_kw:
            # Skip if keyword is explicitly exempted
            if kw in self.exempt_keywords:
                continue
            
            # Skip if this is a legitimate path keyword and path exists in Django
            if (kw in self.legitimate_path_keywords and 
                path_exists and 
                not self._is_malicious_context(request, kw)):
                continue
            
            # Skip if path starts with safe prefix
            if any(path.startswith(prefix) for prefix in self.safe_prefixes if prefix):
                continue
            
            suspicious_kw.add(kw)
        
        # Check segments against suspicious keywords
        for seg in segments:
            is_suspicious = False
            block_reason = ""
            
            # Check if segment is in learned suspicious keywords
            if seg in suspicious_kw:
                is_suspicious = True
                block_reason = f"Learned keyword: {seg}"
            
            # Also check if segment appears to be inherently malicious
            elif (not path_exists and 
                  seg not in self.legitimate_path_keywords and 
                  (self._is_malicious_context(request, seg) or 
                   any(malicious_pattern in seg for malicious_pattern in 
                       ['hack', 'exploit', 'attack', 'malicious', 'evil', 'backdoor', 'inject', 'xss']))):
                is_suspicious = True
                block_reason = f"Inherently suspicious: {seg}"
            
            if is_suspicious:
                # Additional context check before blocking
                if self._is_malicious_context(request, seg) or not path_exists:
                    # Double-check exemption before blocking
                    if not exemption_store.is_exempted(ip):
                        BlacklistManager.block(ip, f"Keyword block: {block_reason}")
                        # Check again after blocking attempt (exempted IPs won't be blocked)
                        if BlacklistManager.is_blocked(ip):
                            return JsonResponse({"error": "blocked"}, status=403)
        return self.get_response(request)


class RateLimitMiddleware:
    def __init__(self, get_response):
        self.get_response = get_response
        # Make rate limiting configurable via Django settings
        self.WINDOW = getattr(settings, "AIWAF_RATE_WINDOW", 10)  # seconds
        self.MAX = getattr(settings, "AIWAF_RATE_MAX", 20)        # soft limit
        self.FLOOD = getattr(settings, "AIWAF_RATE_FLOOD", 40)    # hard limit

    def __call__(self, request):
        # First exemption check - early exit for exempt requests
        if is_exempt(request):
            return self.get_response(request)

        ip = get_ip(request)
        
        # Additional IP-level exemption check
        from .storage import get_exemption_store
        exemption_store = get_exemption_store()
        if exemption_store.is_exempted(ip):
            return self.get_response(request)
            
        key = f"ratelimit:{ip}"
        now = time.time()
        timestamps = cache.get(key, [])
        timestamps = [t for t in timestamps if now - t < self.WINDOW]
        timestamps.append(now)
        cache.set(key, timestamps, timeout=self.WINDOW)
        
        if len(timestamps) > self.FLOOD:
            # Double-check exemption before blocking
            if not exemption_store.is_exempted(ip):
                BlacklistManager.block(ip, "Flood pattern")
                # Check if actually blocked (exempted IPs won't be blocked)
                if BlacklistManager.is_blocked(ip):
                    return JsonResponse({"error": "blocked"}, status=403)
        if len(timestamps) > self.MAX:
            return JsonResponse({"error": "too_many_requests"}, status=429)
        return self.get_response(request)


class AIAnomalyMiddleware(MiddlewareMixin):
    WINDOW = getattr(settings, "AIWAF_WINDOW_SECONDS", 60)
    TOP_N  = getattr(settings, "AIWAF_DYNAMIC_TOP_N", 10)

    def __init__(self, get_response=None):
        super().__init__(get_response)
        # Use the safely loaded global MODEL instead of loading again
        self.model = MODEL

    def process_request(self, request):
        # First exemption check - early exit for exempt requests
        if is_exempt(request):
            return None
            
        request._start_time = time.time()
        ip = get_ip(request)
        
        # Additional IP-level exemption check
        from .storage import get_exemption_store
        exemption_store = get_exemption_store()
        if exemption_store.is_exempted(ip):
            return None
            
        # BlacklistManager handles exemption checking internally
        if BlacklistManager.is_blocked(ip):
            return JsonResponse({"error": "blocked"}, status=403)
        return None

    def process_response(self, request, response):
        # First exemption check - early exit for exempt requests
        if is_exempt(request):
            return response
            
        ip = get_ip(request)
        
        # Additional IP-level exemption check
        from .storage import get_exemption_store
        exemption_store = get_exemption_store()
        if exemption_store.is_exempted(ip):
            return response
            
        now = time.time()
        key = f"aiwaf:{ip}"
        data = cache.get(key, [])
        path_len = len(request.path)
        
        # Use the same scoring logic as trainer.py
        known_path = path_exists_in_django(request.path)
        kw_hits = 0
        if not known_path and not is_exempt_path(request.path):
            kw_hits = sum(1 for kw in STATIC_KW if kw in request.path.lower())

        resp_time = now - getattr(request, "_start_time", now)
        status_code = str(response.status_code)
        status_idx = STATUS_IDX.index(status_code) if status_code in STATUS_IDX else -1
        burst_count = sum(1 for (t, _, _, _) in data if now - t <= 10)
        total_404 = sum(1 for (_, _, st, _) in data if st == 404)
        feats = [path_len, kw_hits, resp_time, status_idx, burst_count, total_404]
        X = np.array(feats, dtype=float).reshape(1, -1)
        
        # Only use AI model if it's available
        if self.model is not None and self.model.predict(X)[0] == -1:
            # AI detected anomaly - but analyze patterns before blocking (like trainer.py)
            
            # Get recent behavior data for this IP to make intelligent blocking decision
            recent_data = [d for d in data if now - d[0] <= 300]  # Last 5 minutes
            
            if recent_data:
                # Calculate behavior metrics similar to trainer.py
                recent_kw_hits = []
                recent_404s = 0
                recent_burst_counts = []
                
                for entry_time, entry_path, entry_status, entry_resp_time in recent_data:
                    # Calculate keyword hits for this entry
                    entry_known_path = path_exists_in_django(entry_path)
                    entry_kw_hits = 0
                    if not entry_known_path and not is_exempt_path(entry_path):
                        entry_kw_hits = sum(1 for kw in STATIC_KW if kw in entry_path.lower())
                    recent_kw_hits.append(entry_kw_hits)
                    
                    # Count 404s
                    if entry_status == 404:
                        recent_404s += 1
                    
                    # Calculate burst for this entry (requests within 10 seconds)
                    entry_burst = sum(1 for (t, _, _, _) in recent_data if abs(entry_time - t) <= 10)
                    recent_burst_counts.append(entry_burst)
                
                # Calculate averages and maximums
                avg_kw_hits = sum(recent_kw_hits) / len(recent_kw_hits) if recent_kw_hits else 0
                max_404s = recent_404s
                avg_burst = sum(recent_burst_counts) / len(recent_burst_counts) if recent_burst_counts else 0
                total_requests = len(recent_data)
                
                # Don't block if it looks like legitimate behavior (same thresholds as trainer.py):
                if (
                    avg_kw_hits < 2 and           # Not hitting many malicious keywords
                    max_404s < 10 and            # Not excessive 404s
                    avg_burst < 15 and           # Not excessive burst activity
                    total_requests < 100         # Not excessive total requests
                ):
                    # Anomalous but looks legitimate - don't block
                    pass
                else:
                    # Double-check exemption before blocking
                    if not exemption_store.is_exempted(ip):
                        BlacklistManager.block(ip, f"AI anomaly + suspicious patterns (kw:{avg_kw_hits:.1f}, 404s:{max_404s}, burst:{avg_burst:.1f})")
                        # Check if actually blocked (exempted IPs won't be blocked)
                        if BlacklistManager.is_blocked(ip):
                            return JsonResponse({"error": "blocked"}, status=403)
            else:
                # No recent data to analyze - be more conservative, only block on very suspicious current request
                if kw_hits >= 2 or status_idx == STATUS_IDX.index("404"):
                    # Double-check exemption before blocking
                    if not exemption_store.is_exempted(ip):
                        BlacklistManager.block(ip, "AI anomaly + immediate suspicious behavior")
                        if BlacklistManager.is_blocked(ip):
                            return JsonResponse({"error": "blocked"}, status=403)

        data.append((now, request.path, response.status_code, resp_time))
        data = [d for d in data if now - d[0] < self.WINDOW]
        cache.set(key, data, timeout=self.WINDOW)
        
        keyword_store = get_keyword_store()
        for seg in re.split(r"\W+", request.path.lower()):
            if len(seg) > 3:
                keyword_store.add_keyword(seg)

        return response


class HoneypotTimingMiddleware(MiddlewareMixin):
    MIN_FORM_TIME = getattr(settings, "AIWAF_MIN_FORM_TIME", 1.0)  # seconds
    
    def process_request(self, request):
        if is_exempt(request):
            return None
            
        ip = get_ip(request)
        
        # Additional IP-level exemption check
        from .storage import get_exemption_store
        exemption_store = get_exemption_store()
        if exemption_store.is_exempted(ip):
            return None
            
        if request.method == "GET":
            # Store timestamp for this IP's GET request  
            # Use a general key for the IP, not path-specific
            cache.set(f"honeypot_get:{ip}", time.time(), timeout=300)  # 5 min timeout
        
        elif request.method == "POST":
            # Check if there was a preceding GET request
            get_time = cache.get(f"honeypot_get:{ip}")
            
            if get_time is None:
                # No GET request - likely bot posting directly
                # But be more lenient for login paths since users might bookmark them
                if not any(request.path.lower().startswith(login_path) for login_path in [
                    "/admin/login/", "/login/", "/accounts/login/", "/auth/login/", "/signin/"
                ]):
                    # Double-check exemption before blocking
                    if not exemption_store.is_exempted(ip):
                        BlacklistManager.block(ip, "Direct POST without GET")
                        # Check if actually blocked (exempted IPs won't be blocked)
                        if BlacklistManager.is_blocked(ip):
                            return JsonResponse({"error": "blocked"}, status=403)
            else:
                # Check timing - be more lenient for login paths
                time_diff = time.time() - get_time
                min_time = self.MIN_FORM_TIME
                
                # Use shorter time threshold for login paths (users can login quickly)
                if any(request.path.lower().startswith(login_path) for login_path in [
                    "/admin/login/", "/login/", "/accounts/login/", "/auth/login/", "/signin/"
                ]):
                    min_time = 0.1  # Very short threshold for login forms
                
                if time_diff < min_time:
                    # Double-check exemption before blocking
                    if not exemption_store.is_exempted(ip):
                        BlacklistManager.block(ip, f"Form submitted too quickly ({time_diff:.2f}s)")
                        # Check if actually blocked (exempted IPs won't be blocked)
                        if BlacklistManager.is_blocked(ip):
                            return JsonResponse({"error": "blocked"}, status=403)
        
        return None


class UUIDTamperMiddleware(MiddlewareMixin):
    def process_view(self, request, view_func, view_args, view_kwargs):
        if is_exempt(request):
            return None
            
        uid = view_kwargs.get("uuid")
        if not uid:
            return None

        ip = get_ip(request)
        
        # Additional IP-level exemption check
        from .storage import get_exemption_store
        exemption_store = get_exemption_store()
        if exemption_store.is_exempted(ip):
            return None
            
        app_label = view_func.__module__.split(".")[0]
        app_cfg   = apps.get_app_config(app_label)
        for Model in app_cfg.get_models():
            if isinstance(Model._meta.pk, UUIDField):
                try:
                    if Model.objects.filter(pk=uid).exists():
                        return None
                except (ValueError, TypeError):
                    continue

        # Double-check exemption before blocking
        if not exemption_store.is_exempted(ip):
            BlacklistManager.block(ip, "UUID tampering")
            # Check if actually blocked (exempted IPs won't be blocked)
            if BlacklistManager.is_blocked(ip):
                return JsonResponse({"error": "blocked"}, status=403)
