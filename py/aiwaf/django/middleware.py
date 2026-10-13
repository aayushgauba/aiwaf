# aiwaf/middleware.py

import time
import re
import os
import glob
import gzip
import warnings
import logging
from datetime import datetime, timedelta
from collections import defaultdict
from django.utils.deprecation import MiddlewareMixin
from django.utils import timezone
from django.http import JsonResponse
from django.core.exceptions import PermissionDenied
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

from .geoip import lookup_country

from .trainer import STATIC_KW, STATUS_IDX, path_exists_in_django
from .blacklist_manager import BlacklistManager
from .models import IPExemption
from .utils import (
    is_exempt,
    get_ip,
    is_ip_exempted,
    is_exempt_path,
    get_exempt_paths,
    is_middleware_disabled,
    get_rate_limit_overrides,
)
from .storage import get_keyword_store
from .settings_compat import apply_legacy_settings
from .model_store import load_model_data, _normalize_storage_mode
from ..core.rust_backend import (
    rust_available,
    validate_headers as rust_validate_headers,
    analyze_recent_behavior as rust_analyze_recent_behavior,
    is_rust_isolation_forest,
    rust_isolation_forest_from_json,
)
from ..core.uuid_tamper import (
    collect_uuid_model_fields,
    is_malformed_uuid,
    is_valid_uuid,
    record_uuid_signal,
)
from ..core.rate_limit import (
    THROTTLE,
    FLOOD_BLOCK,
    build_rate_limit_key,
    normalize_rate_key_mode,
)
from ..core.honeypot import (
    store_honeypot_get_timestamp,
    load_honeypot_get_timestamp,
    clear_honeypot_get_timestamp,
    should_block_get_to_post_only_endpoint,
    evaluate_form_timing,
    ACTION_ALLOW,
    ACTION_BLOCK,
    ACTION_PAGE_EXPIRED,
)
from ..core.ip_keyword import evaluate_keyword_policy
from ..core.request_engine import prepare_request_engine
from ..core.runtime_storage import KeywordStore as RuntimeKeywordStore, CSVStorage
from . import storage as _engine_storage
_DEFAULT_ENGINE_KEYWORD = evaluate_keyword_policy
_DEFAULT_ENGINE_PATH_EXISTS = path_exists_in_django
_DEFAULT_ENGINE_ADD = _engine_storage.CSVKeywordStoreAdapter.add_keyword
_DEFAULT_ENGINE_TOP = _engine_storage.CSVKeywordStoreAdapter.get_top_keywords
_DEFAULT_RUNTIME_ENGINE_ADD = RuntimeKeywordStore.add_keyword
_DEFAULT_RUNTIME_ENGINE_TOP = RuntimeKeywordStore.get_top_keywords
from ..core.method_validation import evaluate_method_policy, ACTION_BLOCK as METHOD_BLOCK
from ..core import header_validation as core_header_validation
from ..core.geo_policy import evaluate_geo_policy, normalize_country_list
_DEFAULT_GEO_POLICY = evaluate_geo_policy
from ..core.block_responses import throttle_response
from ..core.request_context import (
    extract_blacklist_extended_info_from_django_request,
    extract_ip_from_django_request,
    extract_query_keys_from_django_request,
)

apply_legacy_settings()

MODEL_PATH = getattr(
    settings,
    "AIWAF_MODEL_PATH",
    os.path.join(os.path.dirname(__file__), "resources", "model.json")
)

logger = logging.getLogger("aiwaf.django.middleware")
_UUID_MODEL_CACHE = {}
all = "aiwaf.django.middleware.all"

def _log_block(request, reason, status_code=403):
    if not logger.isEnabledFor(logging.DEBUG):
        return
    logger.debug(
        "AIWAF blocked request: reason=%s ip=%s method=%s path=%s status=%s user_agent=%s",
        reason,
        get_ip(request),
        getattr(request, "method", "-"),
        getattr(request, "path", "-"),
        status_code,
        request.META.get("HTTP_USER_AGENT", "-") if hasattr(request, "META") else "-",
    )


def _raise_blocked(request, reason, status_code=403):
    _log_block(request, reason, status_code=status_code)
    raise PermissionDenied("blocked")


class JsonExceptionMiddleware:
    def __init__(self, get_response):
        self.get_response = get_response

    def __call__(self, request):
        return self.get_response(request)

    def process_exception(self, request, exception):
        if request.content_type == "application/json" and isinstance(exception, PermissionDenied):
            message = str(exception) or "Access denied"
            return JsonResponse({"error": message}, status=403)
        return None


def _get_uuid_model_fields(app_label):
    """Return cached UUID model fields for an app (UUID PKs + unique UUID fields)."""
    if app_label in _UUID_MODEL_CACHE:
        return _UUID_MODEL_CACHE[app_label]
    try:
        app_cfg = apps.get_app_config(app_label)
    except LookupError:
        _UUID_MODEL_CACHE[app_label] = []
        return _UUID_MODEL_CACHE[app_label]
    uuid_fields = collect_uuid_model_fields(app_cfg.get_models(), UUIDField)
    _UUID_MODEL_CACHE[app_label] = uuid_fields
    return uuid_fields

def _describe_model_lookup():
    storage_mode = _normalize_storage_mode(getattr(settings, "AIWAF_MODEL_STORAGE", "file"))
    model_path = getattr(settings, "AIWAF_MODEL_PATH", None)
    fallback = getattr(settings, "AIWAF_MODEL_STORAGE_FALLBACK", True)

    if storage_mode == "db":
        primary = "db table aiwaf_aimodelartifact (name='default')"
        if fallback:
            return f"{primary} (fallback file: {model_path})"
        return primary

    if storage_mode == "cache":
        cache_key = getattr(settings, "AIWAF_MODEL_CACHE_KEY", "aiwaf:model")
        primary = f"cache key '{cache_key}'"
        if fallback:
            return f"{primary} (fallback file: {model_path})"
        return primary

    return f"file path {model_path}"


def load_model_safely():
    """Load the AI model with version compatibility checking."""

    # Check if AI is disabled globally
    ai_disabled = getattr(settings, "AIWAF_DISABLE_AI", False)
    if ai_disabled:
        logger.info("AI functionality disabled via AIWAF_DISABLE_AI setting")
        return None

    try:
        # Suppress sklearn version warnings temporarily
        with warnings.catch_warnings():
            warnings.filterwarnings("ignore", category=UserWarning, module="sklearn.base")
            model_data = load_model_data()
            if model_data is None:
                raise ValueError("no model data available")

            # Handle both old format (direct model) and new format (with metadata)
            if isinstance(model_data, dict) and model_data.get("model_backend") == "aiwaf_rust":
                state = model_data.get("model_state")
                if state is None:
                    raise ValueError("missing rust model state")
                model = rust_isolation_forest_from_json(state)
                if model is None:
                    raise ValueError("failed to restore rust model")
                return model
            if isinstance(model_data, dict) and "model" in model_data:
                # New format with metadata
                model = model_data["model"]
                try:
                    import sklearn
                    stored_version = model_data.get("sklearn_version", "unknown")
                    current_version = sklearn.__version__

                    if stored_version != current_version:
                        logger.warning(
                            "Model was trained with sklearn v%s, current v%s",
                            stored_version,
                            current_version,
                        )
                        logger.info("Run 'python manage.py detect_and_train' to update the model if needed.")
                except ImportError:
                    logger.info("sklearn not available, AI functionality disabled")
                    return None

                return model
            else:
                # Old format - direct model object
                logger.info("Using legacy model format. Consider retraining for better compatibility.")
                return model_data

    except Exception as e:
        lookup = _describe_model_lookup()
        if str(e) == "no model data available":
            storage_mode = _normalize_storage_mode(
                getattr(settings, "AIWAF_MODEL_STORAGE", "file")
            )
            if storage_mode == "file":
                logger.info(
                    "AI model not configured at %s; anomaly detection is disabled.",
                    lookup,
                )
            else:
                logger.warning(
                    "AI model not configured at %s; anomaly detection is disabled.",
                    lookup,
                )
            return None
        logger.warning("Could not load AI model from %s: %s", lookup, e)
        logger.info("AI anomaly detection will remain disabled until a model is retrained.")
        logger.info("Run 'python manage.py detect_and_train' to regenerate the model.")
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
    return extract_ip_from_django_request(request)


def _collect_request_headers(request):
    info = extract_blacklist_extended_info_from_django_request(
        request,
        enabled=True,
        max_headers=getattr(settings, "AIWAF_BLACKLIST_MAX_HEADERS", 50),
        max_value_len=getattr(settings, "AIWAF_BLACKLIST_MAX_HEADER_VALUE_LENGTH", 512),
        redact_headers=getattr(
            settings,
            "AIWAF_BLACKLIST_REDACT_HEADERS",
            ["Authorization", "Cookie", "Set-Cookie"],
        ),
    )
    return dict(info.get("headers", {})) if info else {}


def _get_blacklist_extended_info(request):
    if not getattr(settings, "AIWAF_BLACKLIST_STORE_EXTENDED_INFO", False):
        return None
    cache_attr = "_aiwaf_blacklist_extended_info"
    cached = getattr(request, cache_attr, None)
    if cached is not None:
        return cached
    info = extract_blacklist_extended_info_from_django_request(
        request,
        enabled=True,
        max_headers=getattr(settings, "AIWAF_BLACKLIST_MAX_HEADERS", 50),
        max_value_len=getattr(settings, "AIWAF_BLACKLIST_MAX_HEADER_VALUE_LENGTH", 512),
        redact_headers=getattr(
            settings,
            "AIWAF_BLACKLIST_REDACT_HEADERS",
            ["Authorization", "Cookie", "Set-Cookie"],
        ),
    )
    setattr(request, cache_attr, info)
    return info

class IPAndKeywordBlockMiddleware:
    def __init__(self, get_response):
        from aiwaf.core.sql_injection import SQLInjectionPolicy
        self.sql_policy = SQLInjectionPolicy(getattr(settings, "AIWAF_SQL_INJECTION_MODE", None), getattr(settings, "AIWAF_PAYLOAD_MAX_BYTES", None))
        self.get_response = get_response
        self.safe_prefixes = self._collect_safe_prefixes()
        self.exempt_keywords = self._get_exempt_keywords()
        self.legitimate_path_keywords = self._get_legitimate_path_keywords()
        self.malicious_keywords = set(STATIC_KW)  # Initialize malicious keywords
        self.keyword_learning_enabled = getattr(settings, "AIWAF_ENABLE_KEYWORD_LEARNING", True)

    def _get_exempt_keywords(self):
        """Get keywords that should be exempt from blocking"""
        exempt_tokens = set()
        
        # Extract from exempt paths
        for path in get_exempt_paths():
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
        if is_middleware_disabled(request, self.__class__):
            return self.get_response(request)
        # First exemption check - early exit for exempt requests
        if is_exempt(request):
            return self.get_response(request)
            
        raw_path = request.path.lower()
        ip = get_ip(request)
        path = raw_path.lstrip("/")
        
        # Additional IP-level exemption check
        if is_ip_exempted(ip):
            return self.get_response(request)
        
        # BlacklistManager handles exemption checking internally
        if BlacklistManager.is_blocked(ip):
            _raise_blocked(request, "IP already blacklisted", status_code=403)
        
        # Check if path exists in Django - if yes, be more lenient
        from aiwaf.core.sql_injection import inspect_wsgi_request
        finding = inspect_wsgi_request(request, self.sql_policy, django=True)
        if finding:
            _log_block(request, finding.rule, status_code=finding.status)
            return JsonResponse({"error": finding.rule}, status=finding.status)
        path_exists = path_exists_in_django(request.path)
        
        keyword_store = get_keyword_store()
        prepared = None
        if getattr(settings, 'AIWAF_RUST_REQUEST_ENGINE', False):
            from django.urls.converters import get_converters, IntConverter, PathConverter, SlugConverter, StringConverter, UUIDConverter
            standard_converters = {IntConverter, PathConverter, SlugConverter, StringConverter, UUIDConverter}
            runtime_store = _engine_storage.runtime_get_keyword_store()
            if (type(keyword_store) is _engine_storage.CSVKeywordStoreAdapter
                    and type(runtime_store) is RuntimeKeywordStore and type(runtime_store.storage) is CSVStorage
                    and keyword_store.add_keyword is _DEFAULT_ENGINE_ADD
                    and keyword_store.get_top_keywords is _DEFAULT_ENGINE_TOP
                    and getattr(runtime_store.add_keyword, '__func__', None) is _DEFAULT_RUNTIME_ENGINE_ADD
                    and getattr(runtime_store.get_top_keywords, '__func__', None) is _DEFAULT_RUNTIME_ENGINE_TOP
                    and evaluate_keyword_policy is _DEFAULT_ENGINE_KEYWORD
                    and path_exists_in_django is _DEFAULT_ENGINE_PATH_EXISTS
                    and getattr(self._is_malicious_context, '__func__', None) is _DEFAULT_ENGINE_CONTEXT
                    and not any(type(converter) not in standard_converters for converter in get_converters().values())):
                prepared = prepare_request_engine(self, enabled=True, policy=self.sql_policy,
                    path=request.path, query_context=request.META.get('QUERY_STRING', ''),
                    query_keys=extract_query_keys_from_django_request(request), exists=path_exists,
                    learning=self.keyword_learning_enabled, top_n=getattr(settings, 'AIWAF_DYNAMIC_TOP_N', 10),
                    file=runtime_store.storage.file_path, counts=True, static=STATIC_KW,
                    legitimate=self.legitimate_path_keywords, exempt=self.exempt_keywords,
                    prefixes=self.safe_prefixes, malicious=self.malicious_keywords, sql_prechecked=True)
                if prepared:
                    prepared[0](None, None)
        learned_natively = bool(prepared and prepared[1])
        if learned_natively:
            decision = prepared[1][0]
        else:
            dynamic_top = keyword_store.get_top_keywords(getattr(settings, 'AIWAF_DYNAMIC_TOP_N', 10)) if self.keyword_learning_enabled else []
            decision = evaluate_keyword_policy(
            path=request.path,
            query_keys=list(extract_query_keys_from_django_request(request)),
            path_exists=path_exists,
            keyword_learning_enabled=self.keyword_learning_enabled,
            static_keywords=STATIC_KW,
            dynamic_keywords=dynamic_top,
            legitimate_keywords=set(self.legitimate_path_keywords),
            exempt_keywords=set(self.exempt_keywords),
            safe_prefixes=self.safe_prefixes,
            malicious_keywords=self.malicious_keywords,
            is_malicious_context=lambda seg: self._is_malicious_context(request, seg),
        )
        if not learned_natively:
            for seg in decision.learned_keywords:
                keyword_store.add_keyword(seg)

        if decision.block_reason and not is_ip_exempted(ip):
            BlacklistManager.block(
                ip,
                decision.block_reason,
                extended_request_info=_get_blacklist_extended_info(request),
            )
            if BlacklistManager.is_blocked(ip):
                _raise_blocked(request, decision.block_reason, status_code=403)
        return self.get_response(request)


_DEFAULT_ENGINE_CONTEXT = IPAndKeywordBlockMiddleware._is_malicious_context

class RateLimitMiddleware:
    def __init__(self, get_response):
        self.get_response = get_response
        # Make rate limiting configurable via Django settings
        self.WINDOW = getattr(settings, "AIWAF_RATE_WINDOW", 10)  # seconds
        self.MAX = getattr(settings, "AIWAF_RATE_MAX", 20)        # soft limit
        self.FLOOD = getattr(settings, "AIWAF_RATE_FLOOD", 40)    # hard limit
        self.KEY_MODE = normalize_rate_key_mode(getattr(settings, "AIWAF_RATE_KEY_MODE", "ip_path"))
        self.SOFT_BLOCK_BLACKLIST = bool(getattr(settings, "AIWAF_RATE_SOFT_BLOCK_BLACKLIST", False))

    def __call__(self, request):
        if is_middleware_disabled(request, self.__class__):
            return self.get_response(request)
        # First exemption check - early exit for exempt requests
        if is_exempt(request):
            return self.get_response(request)

        ip = get_ip(request)
        
        # Additional IP-level exemption check
        if is_ip_exempted(ip):
            return self.get_response(request)
            
        overrides = get_rate_limit_overrides(request)
        window = overrides.get("WINDOW", self.WINDOW)
        max_requests = overrides.get("MAX", self.MAX)
        flood = overrides.get("FLOOD", self.FLOOD)

        key = build_rate_limit_key(
            "ratelimit",
            ip,
            request.path or "unknown",
            key_mode=self.KEY_MODE,
        )
        now = time.time()
        from .rate_cache import consume_django_rate_limit
        from ..core.rate_limit import RateCacheUnavailable
        try:
            decision = consume_django_rate_limit(
                cache, key,
                now=now,
                window_seconds=window,
                max_requests=max_requests,
                flood_threshold=flood,
            )
        except RateCacheUnavailable:
            return JsonResponse({'error': 'temporarily_unavailable'}, status=503)

        if decision.action == FLOOD_BLOCK:
            # Double-check exemption before blocking
            if not is_ip_exempted(ip):
                BlacklistManager.block(
                    ip,
                    "Flood pattern",
                    extended_request_info=_get_blacklist_extended_info(request),
                )
                # Check if actually blocked (exempted IPs won't be blocked)
                if BlacklistManager.is_blocked(ip):
                    _raise_blocked(request, "Flood pattern", status_code=403)
        if decision.action == THROTTLE:
            if self.SOFT_BLOCK_BLACKLIST:
                BlacklistManager.block(
                    ip,
                    "Rate limit exceeded",
                    extended_request_info=_get_blacklist_extended_info(request),
                )
            payload, status = throttle_response()
            return JsonResponse(payload, status=status)
        return self.get_response(request)


class GeoBlockMiddleware(MiddlewareMixin):
    def __init__(self, get_response=None):
        super().__init__(get_response)
        self.enabled = getattr(settings, "AIWAF_GEO_BLOCK_ENABLED", False)
        self.allow_countries = normalize_country_list(
            getattr(settings, "AIWAF_GEO_ALLOW_COUNTRIES", [])
        )
        self.block_countries = normalize_country_list(
            getattr(settings, "AIWAF_GEO_BLOCK_COUNTRIES", [])
        )
        self.db_path = getattr(settings, "AIWAF_GEOIP_DB_PATH", None)
        self.cache_seconds = getattr(settings, "AIWAF_GEO_CACHE_SECONDS", 3600)
        self.cache_prefix = getattr(settings, "AIWAF_GEO_CACHE_PREFIX", "aiwaf:geo:")

    def process_request(self, request):
        if is_middleware_disabled(request, self.__class__):
            return None
        if not self.enabled:
            return None
        if not (self.allow_countries or self.block_countries):
            return None
        if is_exempt(request):
            return None

        ip = get_ip(request)
        if is_ip_exempted(ip):
            return None

        country = lookup_country(ip, cache_prefix=self.cache_prefix, cache_seconds=self.cache_seconds)
        if not country:
            return None

        country = country.upper()
        dynamic_block = []
        try:
            from .models import GeoBlockedCountry
            dynamic_block = list(
                GeoBlockedCountry.objects.values_list("country_code", flat=True)
            )
        except Exception:
            dynamic_block = []
        from .storage import _is_csv_mode, _ensure_runtime_csv_backend
        if _is_csv_mode() and evaluate_geo_policy is _DEFAULT_GEO_POLICY:
            from ..core.runtime_storage import get_geo_block_store
            _ensure_runtime_csv_backend()
            decision = get_geo_block_store().evaluate_geo_policy(
                country, self.allow_countries, self.block_countries, dynamic_block)
        else:
            decision = evaluate_geo_policy(
                country=country,
                allow_countries=self.allow_countries,
                block_countries=self.block_countries,
                dynamic_blocked=dynamic_block,
            )

        if decision.should_block:
            reason = f"Geo-blocked country: {decision.country}"
            BlacklistManager.block(
                ip,
                reason,
                extended_request_info=_get_blacklist_extended_info(request),
            )
            if BlacklistManager.is_blocked(ip):
                _raise_blocked(request, reason, status_code=403)
        return None


class AIAnomalyMiddleware(MiddlewareMixin):
    WINDOW = getattr(settings, "AIWAF_WINDOW_SECONDS", 60)
    TOP_N  = getattr(settings, "AIWAF_DYNAMIC_TOP_N", 10)

    def __init__(self, get_response=None):
        super().__init__(get_response)
        # Use the safely loaded global MODEL instead of loading again
        self.model = MODEL
        self.min_ai_logs = getattr(settings, "AIWAF_MIN_AI_LOGS", 10000)
        self.ai_logs_sufficient, self.ai_log_count = self._check_ai_log_sufficiency()
        if self.model is not None and not self.ai_logs_sufficient:
            self.model = None
            if logger.isEnabledFor(logging.INFO):
                count_display = self.ai_log_count if self.ai_log_count is not None else "unknown"
                logger.info(
                    "AIWAF AI model disabled due to insufficient logs (%s/%s).",
                    count_display,
                    self.min_ai_logs,
                )
        self.malicious_keywords = set(STATIC_KW)  # Initialize malicious keywords
        self.keyword_learning_enabled = getattr(settings, "AIWAF_ENABLE_KEYWORD_LEARNING", True)

    def _count_log_lines(self, path, limit):
        if limit <= 0:
            return 0
        opener = gzip.open if path.endswith(".gz") else open
        count = 0
        try:
            with opener(path, "rt", errors="ignore") as f:
                for _ in f:
                    count += 1
                    if count >= limit:
                        break
        except OSError:
            return 0
        return count

    def _check_ai_log_sufficiency(self):
        if self.min_ai_logs <= 0:
            return True, None

        count = 0
        log_path = getattr(settings, "AIWAF_ACCESS_LOG", None)

        if log_path and os.path.exists(log_path):
            count += self._count_log_lines(log_path, self.min_ai_logs - count)
            if count >= self.min_ai_logs:
                return True, count

            for path in sorted(glob.glob(f"{log_path}.*")):
                count += self._count_log_lines(path, self.min_ai_logs - count)
                if count >= self.min_ai_logs:
                    return True, count

        try:
            from .models import RequestLog
            cutoff_date = timezone.now() - timedelta(days=30)
            db_count = RequestLog.objects.filter(timestamp__gte=cutoff_date).count()
            count = max(count, db_count)
        except Exception as exc:
            if logger.isEnabledFor(logging.DEBUG):
                logger.debug("AIWAF log sufficiency check failed: %s", exc)

        return count >= self.min_ai_logs, count

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
            any(param in extract_query_keys_from_django_request(request) for param in ['cmd', 'exec', 'system', 'shell']),
            
            # Multiple directory traversal attempts
            request.path.count('../') > 2 or request.path.count('..\\') > 2,
            
            # Encoded attack patterns
            any(encoded in request.path for encoded in ['%2e%2e', '%252e', '%c0%ae']),
        ]
        
        return any(malicious_indicators)

    # Back-compat helpers (used by tests and older integrations)
    def _analyze_recent_behavior_python(self, recent_data):
        from aiwaf.core.anomaly import analyze_recent_behavior_python as core_analyze_recent_behavior_python

        stats = core_analyze_recent_behavior_python(
            recent_data,
            static_keywords=STATIC_KW,
            path_exists=path_exists_in_django,
            is_exempt_path=is_exempt_path,
        )
        return {
            "avg_kw_hits": stats.avg_kw_hits,
            "max_404s": stats.max_404s,
            "avg_burst": stats.avg_burst,
            "total_requests": stats.total_requests,
            "scanning_404s": stats.scanning_404s,
            "legitimate_404s": stats.legitimate_404s,
            "should_block": stats.should_block,
        }

    def _analyze_recent_behavior(self, recent_data):
        if not recent_data:
            return None

        if rust_available():
            rust_payload = []
            for entry_time, entry_path, entry_status, _ in recent_data:
                entry_known_path = path_exists_in_django(entry_path)
                rust_payload.append(
                    {
                        "path_lower": entry_path.lower(),
                        "timestamp": entry_time,
                        "status": int(entry_status),
                        "kw_check": (not entry_known_path and not is_exempt_path(entry_path)),
                    }
                )
            rust_stats = rust_analyze_recent_behavior(rust_payload, STATIC_KW)
            if rust_stats:
                return rust_stats

        return self._analyze_recent_behavior_python(recent_data)

    def process_request(self, request):
        if is_middleware_disabled(request, self.__class__):
            return None
        # First exemption check - early exit for exempt requests
        if is_exempt(request):
            return None
            
        request._start_time = time.time()
        ip = get_ip(request)
        
        # Additional IP-level exemption check
        if is_ip_exempted(ip):
            return None
            
        # BlacklistManager handles exemption checking internally
        if BlacklistManager.is_blocked(ip):
            _raise_blocked(request, "IP already blacklisted", status_code=403)
        return None

    def process_response(self, request, response):
        if is_middleware_disabled(request, self.__class__):
            return response
        # First exemption check - early exit for exempt requests
        if is_exempt(request):
            return response
            
        ip = get_ip(request)
        
        # Additional IP-level exemption check
        if is_ip_exempted(ip):
            return response
            
        from aiwaf.core.anomaly import evaluate_anomaly as core_evaluate_anomaly

        now = time.time()
        key = f"aiwaf:{ip}"
        data = cache.get(key, [])
        resp_time = now - getattr(request, "_start_time", now)

        legitimate_keywords = set()
        if self.keyword_learning_enabled:
            try:
                from .trainer import get_legitimate_keywords
                legitimate_keywords = set(get_legitimate_keywords() or set())
            except Exception:
                legitimate_keywords = set()

        outcome = core_evaluate_anomaly(
            ip=ip,
            path=request.path,
            status_code=int(getattr(response, "status_code", 0) or 0),
            response_time=float(resp_time),
            now=float(now),
            history=data,
            window_seconds=float(self.WINDOW),
            model=self.model,
            static_keywords=STATIC_KW,
            malicious_keywords=STATIC_KW,
            keyword_learning_enabled=bool(self.keyword_learning_enabled),
            path_exists=path_exists_in_django,
            is_exempt_path=is_exempt_path,
            is_malicious_context=lambda seg: self._is_malicious_context(request, seg),
            status_index_values=STATUS_IDX,
            legitimate_keywords=legitimate_keywords,
        )

        cache.set(key, outcome.updated_history, timeout=self.WINDOW)

        if outcome.learned_keywords:
            keyword_store = get_keyword_store()
            for seg in outcome.learned_keywords:
                keyword_store.add_keyword(seg)

        if outcome.block and outcome.reason:
            if not is_ip_exempted(ip):
                BlacklistManager.block(
                    ip,
                    outcome.reason,
                    extended_request_info=_get_blacklist_extended_info(request),
                )
                if BlacklistManager.is_blocked(ip):
                    _raise_blocked(request, outcome.reason, status_code=403)

        # Persist request data for IsolationForest training when DB logger middleware
        # is not the active writer. This avoids duplicate RequestLog rows.
        middleware_db_logging_enabled = bool(
            getattr(settings, "AIWAF_MIDDLEWARE_LOGGING", False)
            and getattr(settings, "AIWAF_MIDDLEWARE_DB", True)
        )
        if not middleware_db_logging_enabled:
            try:
                from .models import RequestLog
                RequestLog.objects.create(
                    ip_address=ip,
                    method=request.method,
                    path=request.path[:500],
                    status_code=int(getattr(response, "status_code", 0) or 0),
                    response_time=float(resp_time),
                    user_agent=request.META.get("HTTP_USER_AGENT", "")[:1000],
                    referer=request.META.get("HTTP_REFERER", "")[:500],
                    content_length=str(response.get("Content-Length", "-"))[:20],
                )
            except Exception:
                pass  # Never let logging break the response

        return response


class HoneypotTimingMiddleware(MiddlewareMixin):
    MIN_FORM_TIME = getattr(settings, "AIWAF_MIN_FORM_TIME", 1.0)  # seconds
    MAX_PAGE_TIME = getattr(settings, "AIWAF_MAX_PAGE_TIME", 240)  # 4 minutes default

    def _is_authenticated_session(self, request):
        """Best effort check that this request belongs to an authenticated session."""
        user = getattr(request, "user", None)
        if user is not None:
            is_authenticated = getattr(user, "is_authenticated", False)
            # Django's AnonymousUser.is_authenticated is a property returning False, but guard callable.
            if callable(is_authenticated):
                is_authenticated = is_authenticated()
            if is_authenticated:
                return True

        session = getattr(request, "session", None)
        if session is not None:
            session_key = getattr(session, "session_key", None)
            if session_key and bool(session.get("_auth_user_id")):
                return True

        return False
    
    def _view_accepts_method(self, request, method):
        """
        Check if the current view accepts the specified HTTP method.
        Be very conservative - only block when we're absolutely certain.
        Handle decorator issues by being permissive when detection fails.
        """
        try:
            from django.urls import resolve
            
            # Resolve the current URL to get the view
            resolved = resolve(request.path)
            view_func = resolved.func
            
            # Handle class-based views
            if hasattr(view_func, 'cls'):
                view_class = view_func.cls
                
                # Check http_method_names attribute (most reliable for CBVs)
                if hasattr(view_class, 'http_method_names'):
                    allowed_methods = [m.upper() for m in view_class.http_method_names]
                    return method.upper() in allowed_methods
                
                # For CBVs without http_method_names, check for method handlers
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
                    return has_handler
                
                # Default for CBVs: be permissive
                return True
            
            # Handle function-based views (including decorated ones)
            else:
                # Try to unwrap decorators to get the actual view function
                actual_func = view_func
                while hasattr(actual_func, '__wrapped__'):
                    actual_func = actual_func.__wrapped__
                
                # Check if the actual function has explicit allowed methods
                if hasattr(actual_func, 'http_method_names'):
                    allowed_methods = [m.upper() for m in actual_func.http_method_names]
                    return method.upper() in allowed_methods
                
                # For function-based views, be very conservative
                # Most Django views accept both GET and POST, so default to allowing
                return True
                
        except Exception as e:
            # If anything fails (decorators, imports, etc.), be permissive
            # Better to allow a legitimate request than block it
            return True
    
    def process_request(self, request):
        if is_middleware_disabled(request, self.__class__):
            return None
        if is_exempt(request):
            return None
            
        ip = get_ip(request)
        
        # Additional IP-level exemption check
        if is_ip_exempted(ip):
            return None

        # Authenticated sessions already proved they loaded the form legitimately; skip timing checks
        if self._is_authenticated_session(request):
            return None
            
        if request.method == "GET":
            decision = evaluate_method_policy(
                method=request.method,
                path=request.path,
                accepts_get=self._view_accepts_method(request, "GET"),
                accepts_post=self._view_accepts_method(request, "POST"),
                accepts_method=self._view_accepts_method(request, request.method),
            )
            if decision.action == METHOD_BLOCK and not is_ip_exempted(ip):
                BlacklistManager.block(
                    ip,
                    decision.reason,
                    extended_request_info=_get_blacklist_extended_info(request),
                )
                if BlacklistManager.is_blocked(ip):
                    _log_block(request, decision.reason, status_code=decision.status_code)
                    return JsonResponse({"error": "blocked", "message": decision.message}, status=decision.status_code)
            
            # Store timestamp for this IP's GET request  
            # Use a general key for the IP, not path-specific
            store_honeypot_get_timestamp(
                lambda key, value, ttl: cache.set(key, value, timeout=ttl),
                ip,
                time.time(),
            )
        
        elif request.method == "POST":
            decision = evaluate_method_policy(
                method=request.method,
                path=request.path,
                accepts_get=self._view_accepts_method(request, "GET"),
                accepts_post=self._view_accepts_method(request, "POST"),
                accepts_method=self._view_accepts_method(request, request.method),
            )
            if decision.action == METHOD_BLOCK and not is_ip_exempted(ip):
                BlacklistManager.block(
                    ip,
                    decision.reason,
                    extended_request_info=_get_blacklist_extended_info(request),
                )
                if BlacklistManager.is_blocked(ip):
                    _log_block(request, decision.reason, status_code=decision.status_code)
                    return JsonResponse({"error": "blocked", "message": decision.message}, status=decision.status_code)
            
            # Check if there was a preceding GET request for timing validation
            get_time = load_honeypot_get_timestamp(cache.get, ip)
            
            if get_time is not None:
                decision = evaluate_form_timing(
                    now=time.time(),
                    get_time=get_time,
                    path=request.path,
                    min_form_time=self.MIN_FORM_TIME,
                    max_page_time=self.MAX_PAGE_TIME,
                )
                if decision.action == ACTION_PAGE_EXPIRED:
                    clear_honeypot_get_timestamp(cache.delete, ip)  # Force fresh GET
                    return JsonResponse({
                        "error": "page_expired", 
                        "message": decision.message or "Page has expired. Please reload and try again.",
                        "reload_required": True
                    }, status=decision.status_code or 409)  # 409 Conflict - client should reload

                if decision.action == ACTION_BLOCK:
                    # Double-check exemption before blocking
                    if not is_ip_exempted(ip):
                        BlacklistManager.block(
                            ip,
                            decision.reason or "Form submitted too quickly",
                            extended_request_info=_get_blacklist_extended_info(request),
                        )
                        # Check if actually blocked (exempted IPs won't be blocked)
                        if BlacklistManager.is_blocked(ip):
                            _raise_blocked(
                                request,
                                decision.reason or "Form submitted too quickly",
                                status_code=decision.status_code or 403,
                            )
        
        else:
            decision = evaluate_method_policy(
                method=request.method,
                path=request.path,
                accepts_get=self._view_accepts_method(request, "GET"),
                accepts_post=self._view_accepts_method(request, "POST"),
                accepts_method=self._view_accepts_method(request, request.method),
            )
            if decision.action == METHOD_BLOCK and not is_ip_exempted(ip):
                BlacklistManager.block(
                    ip,
                    decision.reason,
                    extended_request_info=_get_blacklist_extended_info(request),
                )
                if BlacklistManager.is_blocked(ip):
                    _log_block(request, decision.reason, status_code=decision.status_code)
                    return JsonResponse({"error": "blocked", "message": decision.message}, status=decision.status_code)
        
        return None


class UUIDTamperMiddleware(MiddlewareMixin):
    def _score_config(self):
        return {
            "enabled": bool(getattr(settings, "AIWAF_UUID_SCORE_ENABLED", True)),
            "window_seconds": int(getattr(settings, "AIWAF_UUID_SCORE_WINDOW_SECONDS", 60)),
            "block_threshold": int(getattr(settings, "AIWAF_UUID_SCORE_BLOCK_THRESHOLD", 5)),
            "malformed_weight": int(getattr(settings, "AIWAF_UUID_SCORE_MALFORMED_WEIGHT", 5)),
            "not_found_weight": int(getattr(settings, "AIWAF_UUID_SCORE_NOT_FOUND_WEIGHT", 1)),
            "success_decay": int(getattr(settings, "AIWAF_UUID_SCORE_SUCCESS_DECAY", 2)),
        }

    def process_view(self, request, view_func, view_args, view_kwargs):
        if is_middleware_disabled(request, self.__class__):
            return None
        if is_exempt(request):
            return None
            
        uid = view_kwargs.get("uuid")
        if not uid:
            return None

        ip = get_ip(request)
        
        # Additional IP-level exemption check
        if is_ip_exempted(ip):
            return None
            
        request._aiwaf_uuid_candidate = uid
        request._aiwaf_uuid_ip = ip

        if is_malformed_uuid(uid) and not is_ip_exempted(ip):
            decision = record_uuid_signal(ip, "malformed", config=self._score_config())
            reason = f"UUID tampering score={decision['score']}"
            BlacklistManager.block(
                ip,
                reason,
                extended_request_info=_get_blacklist_extended_info(request),
            )
            # Check if actually blocked (exempted IPs won't be blocked)
            if BlacklistManager.is_blocked(ip):
                _raise_blocked(request, reason, status_code=403)
        return None

    def process_response(self, request, response):
        if is_middleware_disabled(request, self.__class__):
            return response
        if is_exempt(request):
            return response
        uid = getattr(request, "_aiwaf_uuid_candidate", None)
        ip = getattr(request, "_aiwaf_uuid_ip", None)
        if not ip or not is_valid_uuid(uid):
            return response
        if is_ip_exempted(ip):
            return response

        if response.status_code == 404:
            decision = record_uuid_signal(ip, "not_found", config=self._score_config())
            if decision["blocked"]:
                reason = f"UUID tampering score={decision['score']}"
                BlacklistManager.block(
                    ip,
                    reason,
                    extended_request_info=_get_blacklist_extended_info(request),
                )
                if BlacklistManager.is_blocked(ip):
                    _raise_blocked(request, reason, status_code=403)
        elif response.status_code < 400:
            record_uuid_signal(ip, "success", config=self._score_config())
        return response


class HeaderValidationMiddleware(MiddlewareMixin):
    """
    Validates HTTP headers to detect bots and malicious requests
    """
    def __init__(self, get_response):
        super().__init__(get_response)
        self.MAX_HEADER_BYTES = getattr(settings, "AIWAF_MAX_HEADER_BYTES", 32 * 1024)
        self.MAX_HEADER_COUNT = getattr(settings, "AIWAF_MAX_HEADER_COUNT", 100)
        self.MAX_USER_AGENT_LENGTH = getattr(settings, "AIWAF_MAX_USER_AGENT_LENGTH", 500)
        self.MAX_ACCEPT_LENGTH = getattr(settings, "AIWAF_MAX_ACCEPT_LENGTH", 4096)
    
    # Standard browser headers that legitimate requests should have
    REQUIRED_HEADERS = [
        'HTTP_USER_AGENT',
        'HTTP_ACCEPT',
    ]
    
    # Headers that browsers typically send
    BROWSER_HEADERS = [
        'HTTP_ACCEPT_LANGUAGE',
        'HTTP_ACCEPT_ENCODING',
        'HTTP_CONNECTION', 
        'HTTP_CACHE_CONTROL',
    ]
    
    # Suspicious User-Agent patterns
    SUSPICIOUS_USER_AGENTS = [
        r'bot',
        r'crawler',
        r'spider',
        r'scraper', 
        r'curl',
        r'wget',
        r'python',
        r'java',
        r'node',
        r'go-http',
        r'axios',
        r'okhttp',
        r'libwww',
        r'lwp-trivial',
        r'mechanize',
        r'requests',
        r'urllib',
        r'httpie',
        r'postman',
        r'insomnia',
        r'^$',  # Empty user agent
        r'mozilla/4\.0$',  # Fake old browser
        # Note: exact "Mozilla/5.0" is common; avoid flagging it as suspicious.
    ]
    
    # Known legitimate bot user agents to whitelist
    LEGITIMATE_BOTS = [
        r'googlebot',
        r'bingbot', 
        r'slurp',  # Yahoo
        r'duckduckbot',
        r'baiduspider',
        r'yandexbot',
        r'facebookexternalhit',
        r'twitterbot',
        r'linkedinbot',
        r'whatsapp',
        r'telegrambot',
        r'applebot',
        r'pingdom',
        r'uptimerobot',
        r'statuscake',
        r'site24x7',
    ]
    
    # Suspicious header combinations
    SUSPICIOUS_COMBINATIONS = [
        # High version HTTP with old user agent
        {
            'condition': lambda headers: (
                headers.get('SERVER_PROTOCOL', '').startswith('HTTP/2') and
                'mozilla/4.0' in headers.get('HTTP_USER_AGENT', '').lower()
            ),
            'reason': 'HTTP/2 with old browser user agent'
        },
        # No Accept header but has User-Agent
        {
            'condition': lambda headers: (
                headers.get('HTTP_USER_AGENT') and 
                not headers.get('HTTP_ACCEPT')
            ),
            'reason': 'User-Agent present but no Accept header'
        },
        # Accept */* only (very generic)
        {
            'condition': lambda headers: (
                headers.get('HTTP_ACCEPT') == '*/*' and
                not any(h in headers for h in ['HTTP_ACCEPT_LANGUAGE', 'HTTP_ACCEPT_ENCODING'])
            ),
            'reason': 'Generic Accept header without language/encoding'
        },
        # No browser-standard headers at all
        {
            'condition': lambda headers: (
                headers.get('HTTP_USER_AGENT') and
                not any(headers.get(h) for h in ['HTTP_ACCEPT_LANGUAGE', 'HTTP_ACCEPT_ENCODING', 'HTTP_CONNECTION'])
            ),
            'reason': 'Missing all browser-standard headers'
        },
        # Suspicious HTTP version patterns
        {
            'condition': lambda headers: (
                'HTTP_USER_AGENT' in headers and
                headers.get('SERVER_PROTOCOL') == 'HTTP/1.0' and
                'chrome' in headers.get('HTTP_USER_AGENT', '').lower()
            ),
            'reason': 'Modern browser with HTTP/1.0'
        }
    ]

    def process_request(self, request):
        if is_middleware_disabled(request, self.__class__):
            return None
        # Skip if request is exempted
        if is_exempt(request):
            return None
            
        ip = get_ip(request)
        
        # Check IP-level exemption
        if is_ip_exempted(ip):
            return None
            
        # Skip for static files and common paths
        if self._is_static_request(request):
            return None
        
        # Get headers from request.META
        headers = request.META

        required_headers = self._get_required_headers(request)
        min_score = self._get_min_quality_score(required_headers)

        rust_reason = None
        if self._should_use_rust():
            rust_reason = rust_validate_headers(headers, required_headers, min_score)

        reason = core_header_validation.evaluate_header_policy(
            headers,
            method=getattr(request, "method", None),
            config_required_headers=getattr(settings, "AIWAF_REQUIRED_HEADERS", None),
            min_score=min_score,
            max_header_bytes=self.MAX_HEADER_BYTES,
            max_header_count=self.MAX_HEADER_COUNT,
            max_user_agent_length=self.MAX_USER_AGENT_LENGTH,
            max_accept_length=self.MAX_ACCEPT_LENGTH,
            suspicious_user_agents=self.SUSPICIOUS_USER_AGENTS,
            legitimate_bots=self.LEGITIMATE_BOTS,
            suspicious_combinations=self.SUSPICIOUS_COMBINATIONS,
            browser_headers=self.BROWSER_HEADERS,
        )
        if reason:
            return self._block_request(request, ip, reason, request.path)

        if rust_reason:
            return self._block_request(request, ip, rust_reason, request.path)
        
        return None

    def _should_use_rust(self) -> bool:
        return rust_available()
    
    def _is_static_request(self, request):
        """Check if this is a request for static files"""
        static_extensions = ['.css', '.js', '.png', '.jpg', '.jpeg', '.gif', '.ico', '.svg', '.woff', '.woff2', '.ttf']
        path = request.path.lower()
        
        # Check file extensions
        if any(path.endswith(ext) for ext in static_extensions):
            return True
            
        # Check static paths
        static_paths = ['/static/', '/media/', '/assets/', '/favicon.ico']
        if any(path.startswith(static_path) for static_path in static_paths):
            return True
            
        return False
    
    def _get_required_headers(self, request):
        override = getattr(settings, "AIWAF_REQUIRED_HEADERS", None)
        if override is None:
            return list(self.REQUIRED_HEADERS)
        if isinstance(override, (list, tuple)):
            return list(override)
        if isinstance(override, dict):
            method = getattr(request, "method", "").upper()
            headers = override.get(method)
            if headers is None:
                headers = override.get("DEFAULT")
            if headers is None:
                return list(self.REQUIRED_HEADERS)
            return list(headers)
        return list(self.REQUIRED_HEADERS)

    def _get_min_quality_score(self, required_headers):
        default_min = getattr(settings, "AIWAF_HEADER_QUALITY_MIN_SCORE", 3)
        if not required_headers:
            return 0
        return default_min

    def _check_missing_headers(self, headers, required_headers):
        """Check for missing required headers"""
        missing = []
        
        for header in required_headers:
            if not headers.get(header):
                missing.append(header.replace('HTTP_', '').replace('_', '-').lower())
                
        return missing
    
    def _check_user_agent(self, user_agent):
        """Check if user agent is suspicious"""
        if not user_agent:
            return "Empty user agent"
            
        if len(user_agent) > self.MAX_USER_AGENT_LENGTH:
            return f"User-Agent longer than {self.MAX_USER_AGENT_LENGTH} chars"
        
        user_agent_lower = user_agent.lower()
        
        # Check if it's a legitimate bot first
        for legitimate_pattern in self.LEGITIMATE_BOTS:
            if re.search(legitimate_pattern, user_agent_lower):
                return None  # Allow legitimate bots
        
        # Check for suspicious patterns
        for suspicious_pattern in self.SUSPICIOUS_USER_AGENTS:
            if re.search(suspicious_pattern, user_agent_lower, re.IGNORECASE):
                return f"Pattern: {suspicious_pattern}"
                
        # Check for very short user agents (likely fake)
        if len(user_agent) < 10:
            return "Too short"
            
        # Check for very long user agents (possibly malicious)
        if len(user_agent) > self.MAX_USER_AGENT_LENGTH:
            return f"Too long (> {self.MAX_USER_AGENT_LENGTH})"
            
        return None

    def _enforce_header_caps(self, headers):
        """Fail fast for oversized header floods and malformed clients."""
        total_bytes = 0
        header_count = 0

        for key, value in headers.items():
            if not self._is_http_meta_key(key):
                continue

            header_count += 1
            value_str = value if isinstance(value, str) else str(value)
            total_bytes += len(key) + len(value_str)

            if total_bytes > self.MAX_HEADER_BYTES:
                return f"Header bytes exceed {self.MAX_HEADER_BYTES}"

        if header_count > self.MAX_HEADER_COUNT:
            return f"Header count exceeds {self.MAX_HEADER_COUNT}"

        user_agent = headers.get('HTTP_USER_AGENT', '')
        if user_agent and len(user_agent) > self.MAX_USER_AGENT_LENGTH:
            return f"User-Agent longer than {self.MAX_USER_AGENT_LENGTH} chars"

        accept_header = headers.get('HTTP_ACCEPT', '')
        if accept_header and len(accept_header) > self.MAX_ACCEPT_LENGTH:
            return f"Accept header longer than {self.MAX_ACCEPT_LENGTH} chars"

        return None

    def _is_http_meta_key(self, key: str) -> bool:
        return key.startswith('HTTP_') or key in {'CONTENT_TYPE', 'CONTENT_LENGTH'}
    
    def _check_header_combinations(self, headers, required_headers):
        """Check for suspicious header combinations"""
        if not required_headers:
            return None
        required = set(required_headers)
        for combo in self.SUSPICIOUS_COMBINATIONS:
            try:
                if combo.get('reason') == 'User-Agent present but no Accept header' and 'HTTP_ACCEPT' not in required:
                    continue
                if combo['condition'](headers):
                    return combo['reason']
            except Exception:
                # If condition check fails, skip it
                continue
                
        return None
    
    def _calculate_header_quality(self, headers):
        """Calculate a quality score based on header completeness"""
        score = 0
        
        # Basic required headers (2 points each)
        if headers.get('HTTP_USER_AGENT'):
            score += 2
        if headers.get('HTTP_ACCEPT'):
            score += 2
            
        # Browser-standard headers (1 point each)
        for header in self.BROWSER_HEADERS:
            if headers.get(header):
                score += 1
                
        # Bonus points for realistic combinations
        if headers.get('HTTP_ACCEPT_LANGUAGE') and headers.get('HTTP_ACCEPT_ENCODING'):
            score += 1
            
        if headers.get('HTTP_CONNECTION') == 'keep-alive':
            score += 1
            
        # Check for realistic Accept header
        accept = headers.get('HTTP_ACCEPT', '')
        if 'text/html' in accept and 'application/xml' in accept:
            score += 1
            
        return score
    
    def _block_request(self, request, ip, reason, path):
        """Block the request and raise PermissionDenied"""
        # Double-check exemption before blocking
        if not is_ip_exempted(ip):
            BlacklistManager.block(
                ip,
                f"Header validation: {reason}",
                extended_request_info=_get_blacklist_extended_info(request),
            )
            
            # Check if actually blocked (exempted IPs won't be blocked)
            if BlacklistManager.is_blocked(ip):
                _raise_blocked(request, f"Header validation: {reason}", status_code=403)
                
        return None
