# aiwaf/middleware.py

import time
import re
import os
import warnings
from collections import defaultdict
from django.utils.deprecation import MiddlewareMixin
from django.http import JsonResponse
from django.conf import settings
from django.core.cache import cache
from django.db.models import F, UUIDField
from django.apps import apps
from django.urls import get_resolver

# Optional dependencies with graceful fallbacks
try:
    import numpy as np
    NUMPY_AVAILABLE = True
except ImportError:
    np = None
    NUMPY_AVAILABLE = False

try:
    import joblib
    JOBLIB_AVAILABLE = True
except ImportError:
    joblib = None
    JOBLIB_AVAILABLE = False

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
    
    # Check if AI is disabled globally
    ai_disabled = getattr(settings, "AIWAF_DISABLE_AI", False)
    if ai_disabled:
        print("ℹ️  AI functionality disabled via AIWAF_DISABLE_AI setting")
        return None
    
    # Check if required dependencies are available
    if not JOBLIB_AVAILABLE:
        print("ℹ️  joblib not available, AI functionality disabled")
        return None
    
    try:
        import sklearn
    except ImportError:
        print("ℹ️  sklearn not available, AI functionality disabled")
        return None
    
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
        self.malicious_keywords = set(STATIC_KW)  # Initialize malicious keywords

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
                        # Handle include() patterns - be permissive for URL prefixes that route to apps
                        namespace = getattr(pattern, 'namespace', None)
                        if namespace:
                            for segment in re.split(r'[._-]', namespace.lower()):
                                if len(segment) > 2:
                                    keywords.add(segment)
                        
                        # Extract from the pattern itself - improved logic for include() patterns
                        pattern_str = str(pattern.pattern)
                        # Get literal path segments (not regex parts)
                        literal_parts = re.findall(r'([a-zA-Z][a-zA-Z0-9_-]*)', pattern_str)
                        
                        # For include() patterns, be more permissive since they're routing to existing apps
                        # The key insight: if someone includes an app's URLs, the prefix is legitimate by design
                        for part in literal_parts:
                            if len(part) > 2:
                                part_lower = part.lower()
                                # For URLResolver (include patterns), be more permissive
                                # These are URL prefixes that route to actual app functionality
                                keywords.add(part_lower)
                        
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
        
        # Smart learning: only learn from suspicious contexts, never from valid paths
        if not path_exists:  # Only learn from non-existent paths
            for seg in segments:
                # Only learn if it's not a legitimate keyword AND in a suspicious context
                if (seg not in self.legitimate_path_keywords and 
                    seg not in self.exempt_keywords and
                    self._is_malicious_context(request, seg)):
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
                # Additional context check before blocking - be more conservative with valid paths
                if path_exists:
                    # For valid paths, only block if there are VERY strong malicious indicators
                    very_strong_indicators = [
                        # Multiple attack patterns in same request
                        sum([
                            '../' in request.path, '..\\' in request.path,
                            any(param in request.GET for param in ['cmd', 'exec', 'system']),
                            request.path.count('%') > 5,  # Heavy URL encoding
                            len([s for s in segments if s in self.malicious_keywords]) > 2
                        ]) >= 2,
                        
                        # Obvious attack attempts on valid paths
                        any(attack in request.path.lower() for attack in [
                            'union+select', 'drop+table', '<script', 'javascript:',
                            'onload=', 'onerror=', '${', '{{', 'eval('
                        ])
                    ]
                    
                    if not any(very_strong_indicators):
                        continue  # Skip blocking for valid paths without very strong indicators
                
                # For non-existent paths or paths with very strong indicators, proceed with blocking
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
        self.malicious_keywords = set(STATIC_KW)  # Initialize malicious keywords

    def _is_malicious_context(self, request, keyword):
        """
        Determine if a keyword appears in a malicious context.
        Only learn keywords when we have strong indicators of malicious intent.
        """
        # Don't learn from valid Django paths
        if path_exists_in_django(request.path):
            return False
            
        # Strong malicious indicators
        malicious_indicators = [
            # Multiple consecutive suspicious segments
            len([seg for seg in re.split(r"\W+", request.path) if seg in self.malicious_keywords]) > 1,
            
            # Common attack patterns
            any(pattern in request.path.lower() for pattern in [
                '../', '..\\', '.env', 'wp-admin', 'phpmyadmin', 'config',
                'backup', 'database', 'mysql', 'passwd', 'shadow'
            ]),
            
            # Suspicious query parameters
            any(param in request.GET for param in ['cmd', 'exec', 'system', 'shell']),
            
            # Multiple directory traversal attempts
            request.path.count('../') > 2 or request.path.count('..\\') > 2,
            
            # Encoded attack patterns
            any(encoded in request.path for encoded in ['%2e%2e', '%252e', '%c0%ae']),
        ]
        
        return any(malicious_indicators)

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
        
        # Only use AI model if it's available and numpy is available
        if self.model is not None and NUMPY_AVAILABLE:
            X = np.array(feats, dtype=float).reshape(1, -1)
            
            if self.model.predict(X)[0] == -1:
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
        
        # Only learn keywords from 404 responses (not found) on non-existent paths
        # This prevents learning from 403 (blocked IPs accessing legitimate paths) or other error codes
        if (response.status_code == 404 and not known_path and not is_exempt_path(request.path)):
            keyword_store = get_keyword_store()
            # Get legitimate keywords to avoid learning them
            from .trainer import get_legitimate_keywords
            legitimate_keywords = get_legitimate_keywords()
            
            for seg in re.split(r"\W+", request.path.lower()):
                if (len(seg) > 3 and 
                    seg not in STATIC_KW and  # Don't re-learn static keywords
                    seg not in legitimate_keywords and  # Don't learn legitimate keywords
                    self._is_malicious_context(request, seg)):  # Only learn in malicious context
                    keyword_store.add_keyword(seg)

        return response


class HoneypotTimingMiddleware(MiddlewareMixin):
    MIN_FORM_TIME = getattr(settings, "AIWAF_MIN_FORM_TIME", 1.0)  # seconds
    MAX_PAGE_TIME = getattr(settings, "AIWAF_MAX_PAGE_TIME", 240)  # 4 minutes default
    
    def _view_accepts_method(self, request, method):
        """Check if the current view/URL pattern accepts the specified HTTP method"""
        try:
            from django.urls import resolve
            from django.urls.resolvers import URLResolver, URLPattern
            
            # Resolve the current URL to get the view
            resolved = resolve(request.path)
            view_func = resolved.func
            
            # Handle class-based views
            if hasattr(view_func, 'cls'):
                view_class = view_func.cls
                
                # Check http_method_names attribute (most reliable)
                if hasattr(view_class, 'http_method_names'):
                    allowed_methods = [m.upper() for m in view_class.http_method_names]
                    return method.upper() in allowed_methods
                
                # Check for method-handling methods
                method_handlers = {
                    'GET': ['get'],
                    'POST': ['post', 'form_valid', 'form_invalid'],
                    'PUT': ['put'],
                    'PATCH': ['patch'],
                    'DELETE': ['delete']
                }
                
                if method.upper() in method_handlers:
                    handlers = method_handlers[method.upper()]
                    has_handler = any(hasattr(view_class, handler) for handler in handlers)
                    if has_handler:
                        return True
                    
                    # If no handler found, check if it's a common method that should be rejected
                    if method.upper() in ['GET', 'POST', 'PUT', 'DELETE', 'PATCH']:
                        return False
                
                # Default: assume method is allowed for class-based views
                return True
            
            # Handle function-based views
            else:
                # Check if view has explicit allowed methods
                if hasattr(view_func, 'http_method_names'):
                    allowed_methods = [m.upper() for m in view_func.http_method_names]
                    return method.upper() in allowed_methods
                
                # For function-based views, inspect the source code
                import inspect
                try:
                    source = inspect.getsource(view_func)
                    method_upper = method.upper()
                    
                    # Look for method handling in the source
                    if f'request.method' in source and method_upper in source:
                        return True
                    
                    # Look for method-specific patterns
                    method_patterns = {
                        'GET': ['request.GET', 'GET'],
                        'POST': ['request.POST', 'POST', 'form.is_valid()'],
                        'PUT': ['PUT', 'request.PUT'],
                        'DELETE': ['DELETE', 'request.DELETE']
                    }
                    
                    if method.upper() in method_patterns:
                        patterns = method_patterns[method.upper()]
                        if any(pattern in source for pattern in patterns):
                            return True
                            
                except (OSError, TypeError):
                    # Can't get source, make educated guess
                    pass
                
                # Check URL pattern name for method-specific endpoints
                if resolved.url_name:
                    url_name_lower = resolved.url_name.lower()
                    
                    # POST-only patterns
                    post_only_patterns = ['create', 'submit', 'upload', 'process']
                    # GET-only patterns  
                    get_only_patterns = ['list', 'detail', 'view', 'display']
                    
                    if method.upper() == 'POST':
                        if any(pattern in url_name_lower for pattern in post_only_patterns):
                            return True
                        if any(pattern in url_name_lower for pattern in get_only_patterns):
                            return False
                    elif method.upper() == 'GET':
                        if any(pattern in url_name_lower for pattern in get_only_patterns):
                            return True
                        if any(pattern in url_name_lower for pattern in post_only_patterns):
                            return False
                
                # Default: assume function-based views accept common methods
                return method.upper() in ['GET', 'POST', 'HEAD', 'OPTIONS']
                
        except Exception as e:
            # If we can't determine, err on the side of caution and allow
            print(f"AIWAF: Could not determine {method} capability for {request.path}: {e}")
            return True
    
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
            # ENHANCEMENT: Check if this view accepts GET requests
            if not self._view_accepts_method(request, 'GET'):
                # This view is POST-only, but received a GET - likely scanning/probing
                if not exemption_store.is_exempted(ip):
                    BlacklistManager.block(ip, f"GET to POST-only view: {request.path}")
                    if BlacklistManager.is_blocked(ip):
                        return JsonResponse({
                            "error": "blocked", 
                            "message": f"GET not allowed for {request.path}"
                        }, status=405)  # Method Not Allowed
            
            # Store timestamp for this IP's GET request  
            # Use a general key for the IP, not path-specific
            cache.set(f"honeypot_get:{ip}", time.time(), timeout=300)  # 5 min timeout
        
        elif request.method == "POST":
            # ENHANCEMENT: Check if this view actually accepts POST requests
            if not self._view_accepts_method(request, 'POST'):
                # This view is GET-only, but received a POST - likely malicious
                if not exemption_store.is_exempted(ip):
                    BlacklistManager.block(ip, f"POST to GET-only view: {request.path}")
                    if BlacklistManager.is_blocked(ip):
                        return JsonResponse({
                            "error": "blocked", 
                            "message": f"POST not allowed for {request.path}"
                        }, status=405)  # Method Not Allowed
            
            # Check if there was a preceding GET request for timing validation
            get_time = cache.get(f"honeypot_get:{ip}")
            
            if get_time is not None:
                # Check timing - be more lenient for login paths
                time_diff = time.time() - get_time
                min_time = self.MIN_FORM_TIME
                
                # ENHANCEMENT 2: Check for page timeout (4+ minutes)
                if time_diff > self.MAX_PAGE_TIME:
                    # Page has been open too long - suspicious or stale session
                    # Don't block immediately, but require a fresh page load
                    cache.delete(f"honeypot_get:{ip}")  # Force fresh GET
                    return JsonResponse({
                        "error": "page_expired", 
                        "message": "Page has expired. Please reload and try again.",
                        "reload_required": True
                    }, status=409)  # 409 Conflict - client should reload
                
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
        
        else:
            # Handle other HTTP methods (PUT, DELETE, PATCH, etc.)
            if request.method not in ['GET', 'POST', 'HEAD', 'OPTIONS']:
                # Check if this view supports the requested method
                if not self._view_accepts_method(request, request.method):
                    if not exemption_store.is_exempted(ip):
                        BlacklistManager.block(ip, f"{request.method} to view that doesn't support it: {request.path}")
                        if BlacklistManager.is_blocked(ip):
                            return JsonResponse({
                                "error": "blocked", 
                                "message": f"{request.method} not allowed for {request.path}"
                            }, status=405)  # Method Not Allowed
        
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
