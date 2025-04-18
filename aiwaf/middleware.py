# aiwaf/middleware.py

import time
import re
import os
import numpy as np
import joblib

from collections import defaultdict
from django.utils.deprecation import MiddlewareMixin
from django.http import JsonResponse
from django.conf import settings
from django.core.cache import cache
from django.db.models import F
from django.apps import apps

from .blacklist_manager import BlacklistManager
from .models import DynamicKeyword

# ─── Model loading with fallback ────────────────────────────────────────────
MODEL_PATH = getattr(
    settings,
    "AIWAF_MODEL_PATH",
    os.path.join(os.path.dirname(__file__), "resources", "model.pkl")
)
MODEL = joblib.load(MODEL_PATH)

# ─── Static keywords default ────────────────────────────────────────────────
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


class IPBlockMiddleware:
    def __init__(self, get_response):
        self.get_response = get_response

    def __call__(self, request):
        ip = get_ip(request)
        if BlacklistManager.is_blocked(ip):
            return JsonResponse({"error": "blocked"}, status=403)
        return self.get_response(request)


class RateLimitMiddleware:
    WINDOW = 10
    MAX    = 20
    FLOOD  = 10

    def __init__(self, get_response):
        self.get_response = get_response
        self.logs = defaultdict(list)

    def __call__(self, request):
        ip  = get_ip(request)
        now = time.time()
        recs = [t for t in self.logs[ip] if now - t < self.WINDOW]
        recs.append(now)
        self.logs[ip] = recs

        if len(recs) > self.MAX:
            return JsonResponse({"error": "too_many_requests"}, status=429)
        if len(recs) > self.FLOOD:
            BlacklistManager.block(ip, "Flood pattern")
            return JsonResponse({"error": "blocked"}, status=403)

        return self.get_response(request)


class AIAnomalyMiddleware(MiddlewareMixin):
    WINDOW = getattr(settings, "AIWAF_WINDOW_SECONDS", 60)
    TOP_N  = getattr(settings, "AIWAF_DYNAMIC_TOP_N", 10)

    def process_request(self, request):
        ip = get_ip(request)
        if BlacklistManager.is_blocked(ip):
            return JsonResponse({"error": "blocked"}, status=403)

        now = time.time()
        key = f"aiwaf:{ip}"
        data = cache.get(key, [])
        # TODO: you may want to capture real status & response_time in process_response
        data.append((now, request.path, 0, 0.0))
        data = [d for d in data if now - d[0] < self.WINDOW]
        cache.set(key, data, timeout=self.WINDOW)

        # update dynamic‐keyword counts
        for seg in re.split(r"\W+", request.path.lower()):
            if len(seg) > 3:
                obj, _ = DynamicKeyword.objects.get_or_create(keyword=seg)
                DynamicKeyword.objects.filter(pk=obj.pk).update(count=F("count") + 1)

        if len(data) < 5:
            return None

        # pull top‐N dynamic tokens
        top_dynamic = list(
            DynamicKeyword.objects
            .order_by("-count")
            .values_list("keyword", flat=True)[: self.TOP_N]
        )
        ALL_KW = set(STATIC_KW) | set(top_dynamic)

        total    = len(data)
        ratio404 = sum(1 for (_, _, st, _) in data if st == 404) / total
        hits     = sum(any(kw in path.lower() for kw in ALL_KW) for (_, path, _, _) in data)
        avg_rt   = np.mean([rt for (_, _, _, rt) in data]) if data else 0.0
        ivs      = [data[i][0] - data[i - 1][0] for i in range(1, total)]
        avg_iv   = np.mean(ivs) if ivs else 0.0

        X = np.array([[total, ratio404, hits, avg_rt, avg_iv]], dtype=float)
        if MODEL.predict(X)[0] == -1:
            BlacklistManager.block(ip, "AI anomaly")
            return JsonResponse({"error": "blocked"}, status=403)

        return None


class HoneypotMiddleware(MiddlewareMixin):
    def process_view(self, request, view_func, view_args, view_kwargs):
        trap = request.POST.get(getattr(settings, "AIWAF_HONEYPOT_FIELD", "hp_field"), "")
        if trap:
            ip = get_ip(request)
            BlacklistManager.block(ip, "HONEYPOT triggered")
            return JsonResponse({"error": "bot_detected"}, status=403)
        return None


class UUIDTamperMiddleware(MiddlewareMixin):
    def process_view(self, request, view_func, view_args, view_kwargs):
        uid = view_kwargs.get("uuid")
        if not uid:
            return None

        ip = get_ip(request)
        app_label = view_func.__module__.split(".")[0]
        app_cfg   = apps.get_app_config(app_label)
        for Model in app_cfg.get_models():
            if Model.objects.filter(pk=uid).exists():
                return None

        BlacklistManager.block(ip, "UUID tampering")
        return JsonResponse({"error": "blocked"}, status=403)
