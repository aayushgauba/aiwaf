# aiwaf/middleware.py

import time
import re
import os
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
from .trainer import STATIC_KW, STATUS_IDX, is_exempt_path, path_exists_in_django
from .blacklist_manager import BlacklistManager
from .models import DynamicKeyword, IPExemption
def is_ip_exempted(ip):
    return IPExemption.objects.filter(ip_address=ip).exists()

def is_exempt_path(path):
    path = path.lower()
    
    # Default login paths that should always be exempt
    default_login_paths = [
        "/admin/login/",
        "/admin/",
        "/login/",
        "/accounts/login/",
        "/auth/login/",
        "/signin/",
    ]
    
    # Check default login paths
    for login_path in default_login_paths:
        if path.startswith(login_path):
            return True
    
    # Check user-configured exempt paths
    exempt_paths = getattr(settings, "AIWAF_EXEMPT_PATHS", [])
    for exempt in exempt_paths:
        if path == exempt or path.startswith(exempt.rstrip("/") + "/"):
            return True
    
    return False

MODEL_PATH = getattr(
    settings,
    "AIWAF_MODEL_PATH",
    os.path.join(os.path.dirname(__file__), "resources", "model.pkl")
)
MODEL = joblib.load(MODEL_PATH)

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
        raw_path = request.path.lower()
        if is_exempt_path(raw_path):
            return self.get_response(request)
        ip = get_ip(request)
        path = raw_path.lstrip("/")
        if is_ip_exempted(ip):
            return self.get_response(request)
        if BlacklistManager.is_blocked(ip):
            return JsonResponse({"error": "blocked"}, status=403)
        segments = [seg for seg in re.split(r"\W+", path) if len(seg) > 3]
        for seg in segments:
            obj, _ = DynamicKeyword.objects.get_or_create(keyword=seg)
            DynamicKeyword.objects.filter(pk=obj.pk).update(count=F("count") + 1)
        dynamic_top = list(
            DynamicKeyword.objects
            .order_by("-count")
            .values_list("keyword", flat=True)[: getattr(settings, "AIWAF_DYNAMIC_TOP_N", 10)]
        )
        all_kw = set(STATIC_KW) | set(dynamic_top)
        suspicious_kw = {
            kw for kw in all_kw
            if not any(path.startswith(prefix) for prefix in self.safe_prefixes if prefix)
        }
        for seg in segments:
            if seg in suspicious_kw:
                if not is_ip_exempted(ip):
                    BlacklistManager.block(ip, f"Keyword block: {seg}")
                    return JsonResponse({"error": "blocked"}, status=403)
        return self.get_response(request)


class RateLimitMiddleware:
    WINDOW = 10  # seconds
    MAX = 20     # soft limit
    FLOOD = 40   # hard limit

    def __init__(self, get_response):
        self.get_response = get_response

    def __call__(self, request):
        if is_exempt_path(request.path):
            return self.get_response(request)

        ip = get_ip(request)
        key = f"ratelimit:{ip}"
        now = time.time()
        timestamps = cache.get(key, [])
        timestamps = [t for t in timestamps if now - t < self.WINDOW]
        timestamps.append(now)
        cache.set(key, timestamps, timeout=self.WINDOW)
        if len(timestamps) > self.FLOOD:
            if not is_ip_exempted(ip):
                BlacklistManager.block(ip, "Flood pattern")
                return JsonResponse({"error": "blocked"}, status=403)
        if len(timestamps) > self.MAX:
            return JsonResponse({"error": "too_many_requests"}, status=429)
        return self.get_response(request)


class AIAnomalyMiddleware(MiddlewareMixin):
    WINDOW = getattr(settings, "AIWAF_WINDOW_SECONDS", 60)
    TOP_N  = getattr(settings, "AIWAF_DYNAMIC_TOP_N", 10)

    def __init__(self, get_response=None):
        super().__init__(get_response)
        model_path = os.path.join(os.path.dirname(__file__), "resources", "model.pkl")
        self.model = joblib.load(model_path)

    def process_request(self, request):
        if is_exempt_path(request.path):
            return None
        request._start_time = time.time()
        ip = get_ip(request)
        if is_ip_exempted(ip):
            return None
        if BlacklistManager.is_blocked(ip):
            return JsonResponse({"error": "blocked"}, status=403)
        return None

    def process_response(self, request, response):
        if is_exempt_path(request.path):
            return response
        ip = get_ip(request)
        now = time.time()
        key = f"aiwaf:{ip}"
        data = cache.get(key, [])
        path_len = len(request.path)
        if not path_exists_in_django(request.path) and not is_exempt_path(request.path):
            kw_hits = sum(1 for kw in STATIC_KW if kw in request.path.lower())
        else:
            kw_hits = 0

        resp_time = now - getattr(request, "_start_time", now)
        status_code = str(response.status_code)
        status_idx = STATUS_IDX.index(status_code) if status_code in STATUS_IDX else -1
        burst_count = sum(1 for (t, _, _, _) in data if now - t <= 10)
        total_404 = sum(1 for (_, _, st, _) in data if st == 404)
        feats = [path_len, kw_hits, resp_time, status_idx, burst_count, total_404]
        X = np.array(feats, dtype=float).reshape(1, -1)
        if self.model.predict(X)[0] == -1:
            if not is_ip_exempted(ip):
                BlacklistManager.block(ip, "AI anomaly")
                return JsonResponse({"error": "blocked"}, status=403)

        data.append((now, request.path, response.status_code, resp_time))
        data = [d for d in data if now - d[0] < self.WINDOW]
        cache.set(key, data, timeout=self.WINDOW)
        for seg in re.split(r"\W+", request.path.lower()):
            if len(seg) > 3:
                obj, _ = DynamicKeyword.objects.get_or_create(keyword=seg)
                DynamicKeyword.objects.filter(pk=obj.pk).update(count=F("count") + 1)

        return response


class HoneypotTimingMiddleware(MiddlewareMixin):
    MIN_FORM_TIME = getattr(settings, "AIWAF_MIN_FORM_TIME", 1.0)  # seconds
    
    def process_request(self, request):
        if is_exempt_path(request.path):
            return None
            
        ip = get_ip(request)
        if is_ip_exempted(ip):
            return None
            
        if request.method == "GET":
            # Store timestamp for this IP's GET request
            cache.set(f"honeypot_get:{ip}", time.time(), timeout=300)  # 5 min timeout
        
        elif request.method == "POST":
            # Check if there was a preceding GET request
            get_time = cache.get(f"honeypot_get:{ip}")
            
            if get_time is None:
                # No GET request - likely bot posting directly
                BlacklistManager.block(ip, "Direct POST without GET")
                return JsonResponse({"error": "blocked"}, status=403)
            
            # Check timing
            time_diff = time.time() - get_time
            if time_diff < self.MIN_FORM_TIME:
                # Posted too quickly - likely bot
                BlacklistManager.block(ip, f"Form submitted too quickly ({time_diff:.2f}s)")
                return JsonResponse({"error": "blocked"}, status=403)
        
        return None


class UUIDTamperMiddleware(MiddlewareMixin):
    def process_view(self, request, view_func, view_args, view_kwargs):
        if is_exempt_path(request.path):
            return None
        uid = view_kwargs.get("uuid")
        if not uid:
            return None

        ip = get_ip(request)
        app_label = view_func.__module__.split(".")[0]
        app_cfg   = apps.get_app_config(app_label)
        for Model in app_cfg.get_models():
            if isinstance(Model._meta.pk, UUIDField):
                try:
                    if Model.objects.filter(pk=uid).exists():
                        return None
                except (ValueError, TypeError):
                    continue

        if not is_ip_exempted(ip):
            BlacklistManager.block(ip, "UUID tampering")
            return JsonResponse({"error": "blocked"}, status=403)
