"""Django adapter for an explicitly configured Rust-owned CSV pipeline."""
from django.conf import settings
from django.http import HttpResponse
from django.urls import resolve, Resolver404
from aiwaf.core.csv_pipeline import CSVPipeline, validate_fact_callback, fact_value
from aiwaf.core.honeypot import is_authenticated_session_context
from aiwaf.core.request_context import extract_ip_from_django_request
from .geoip import lookup_country


class NativeAIWAFMiddleware:
    def __init__(self, get_response):
        self.get_response = get_response
        self.pipeline = CSVPipeline(getattr(settings, "AIWAF_CSV_PIPELINE", {}))
        self.country_lookup = getattr(settings, "AIWAF_CSV_PIPELINE_COUNTRY_LOOKUP", None)
        validate_fact_callback(self.country_lookup)
        model = getattr(settings, "AIWAF_CSV_PIPELINE_MODEL", None)
        if model is not None:
            self.pipeline.native.set_model(model)

    def __call__(self, request):
        endpoint, exists = None, False
        try:
            match = resolve(request.path_info, urlconf=getattr(request, "urlconf", None))
            endpoint, exists = match.func, True
        except Resolver404:
            pass
        # Django function views do not declare their supported methods. Preserve
        # conservative acceptance; class-based views expose http_method_names.
        methods = {"GET", "POST", "HEAD", "OPTIONS", "PUT", "PATCH", "DELETE", "TRACE", "CONNECT"}
        view_class = getattr(endpoint, "view_class", None)
        if view_class:
            methods = {m.upper() for m in view_class.http_method_names if hasattr(view_class, m)}
        ip = extract_ip_from_django_request(request)
        lookup = self.country_lookup
        query, body, exhausted = self.pipeline.capture_wsgi(request, django=True)
        ctx, status, payload = self.pipeline.begin(ip=ip, path=request.path, method=request.method,
            headers={k: str(v) for k, v in request.META.items() if k.startswith("HTTP_") or k in {"CONTENT_TYPE", "CONTENT_LENGTH", "SERVER_PROTOCOL"}},
            query=query, body=body, exists=exists, methods=methods, endpoint=endpoint,
            country=(fact_value(lookup, ip) if lookup else lookup_country(ip, cache_prefix="aiwaf_geo", cache_seconds=3600)) if self.pipeline.needs_country else "", exhausted=exhausted,
            authenticated=is_authenticated_session_context(getattr(request, "user", None), getattr(request, "session", None)))
        response = HttpResponse(payload, status=status, content_type="application/json") if status else self.get_response(request)
        final_status, final_payload = self.pipeline.finish(ctx, response.status_code, response.get("Content-Length", "-"))
        if final_payload != "null":
            return HttpResponse(final_payload, status=final_status, content_type="application/json")
        return response
