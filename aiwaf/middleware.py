import time
import numpy as np
import joblib
from collections import defaultdict
from django.utils.deprecation import MiddlewareMixin
from django.http import JsonResponse
from django.conf import settings
from django.core.cache import cache
from django.urls import resolve
from django.apps import apps
from .blacklist_manager import BlacklistManager

try:
    MODEL_PATH = settings.AIWAF_MODEL_PATH
except AttributeError:
    import importlib.resources
    MODEL_PATH = importlib.resources.files("aiwaf").joinpath("resources/model.pkl")

MODEL = joblib.load(MODEL_PATH)

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
    WINDOW = getattr(settings, "AIWAF_RATE_WINDOW", 10)
    MAX = getattr(settings, "AIWAF_RATE_MAX", 20)
    FLOOD = getattr(settings, "AIWAF_RATE_FLOOD", 10)
    def __init__(self, get_response):
        self.get_response = get_response
        self.logs = defaultdict(list)
    def __call__(self, request):
        ip = get_ip(request)
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
    WINDOW_SECONDS = getattr(settings, "AIWAF_WINDOW_SECONDS", 60)
    def process_request(self, request):
        ip = get_ip(request)
        if BlacklistManager.is_blocked(ip):
            return JsonResponse({"error": "blocked"}, status=403)
        now = time.time()
        key = f"aiwaf:{ip}"
        data = cache.get(key, [])
        data.append((now, request.path, 0, 0.0))
        data = [d for d in data if now - d[0] < self.WINDOW_SECONDS]
        cache.set(key, data, timeout=self.WINDOW_SECONDS)
        if len(data) < 5:
            return None
        total = len(data)
        ratio_404 = sum(1 for (_, _, st, _) in data if st == 404) / total
        hits = sum(
            any(k in path.lower() for k in settings.AIWAF_MALICIOUS_KEYWORDS)
            for (_, path, _, _) in data
        )
        avg_rt = np.mean([rt for (_, _, _, rt) in data]) if data else 0.0
        intervals = [
            data[i][0] - data[i-1][0] for i in range(1, total)
        ]
        avg_iv = np.mean(intervals) if intervals else 0.0
        X = np.array([[total, ratio_404, hits, avg_rt, avg_iv]], dtype=float)
        if MODEL.predict(X)[0] == -1:
            BlacklistManager.block(ip, "AI anomaly")
            return JsonResponse({"error": "blocked"}, status=403)
        return None


class HoneypotMiddleware(MiddlewareMixin):
    def process_view(self, request, view_func, view_args, view_kwargs):
        trap = request.POST.get(settings.AIWAF_HONEYPOT_FIELD, "")
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
        app_label = view_kwargs.get("app_label") or view_func.__module__.split('.')[0]
        app_config = apps.get_app_config(app_label)
        for Model in app_config.get_models():
            if Model.objects.filter(pk=uid).exists():
                return None
        BlacklistManager.block(ip, "UUID tampering")
        return JsonResponse({"error": "blocked"}, status=403)