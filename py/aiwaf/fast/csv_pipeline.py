"""Pure ASGI adapter: inspect a bounded body prefix and replay exact messages."""
from functools import partial
from starlette.concurrency import run_in_threadpool
from starlette.requests import Request
from starlette.responses import Response
from starlette.routing import Match
from aiwaf.core.csv_pipeline import CSVPipeline, environ_headers, validate_fact_callback, fact_value
from aiwaf.core.request_context import resolve_ip_from_fastapi_request
from .geoip import get_country_for_ip

_ANY_METHOD = {"GET", "POST", "HEAD", "OPTIONS", "PUT", "PATCH", "DELETE", "TRACE", "CONNECT"}


def route_facts(router, scope):
    """Resolve mounts without treating every descendant as an existing endpoint."""
    methods, exists = set(), False
    for route in getattr(router, "routes", ()):
        match, child = route.matches(scope)
        if match not in (Match.FULL, Match.PARTIAL):
            continue
        if hasattr(route, "routes"):
            endpoint, nested_exists, nested_methods = route_facts(route, {**scope, **child})
            if nested_exists:
                return endpoint, nested_exists, nested_methods
            continue
        exists = True
        methods.update(getattr(route, "methods", None) or _ANY_METHOD)
        if match == Match.FULL:
            return child.get("endpoint"), True, methods
    return None, exists, methods if exists else _ANY_METHOD


class NativeAIWAFMiddleware:
    def __init__(self, app, config=None, *, model=None, country_lookup=None, authenticated=None, honeypot_cache=None):
        validate_fact_callback(country_lookup)
        validate_fact_callback(authenticated)
        self.app = app
        self.pipeline = CSVPipeline(config, model=model, honeypot_cache=honeypot_cache)
        self.cache_io = self.pipeline.profile.get("honeypot_backend") == "cache"
        self.country_lookup = country_lookup
        self.authenticated = authenticated

    async def __call__(self, scope, receive, send):
        if scope["type"] != "http":
            return await self.app(scope, receive, send)
        request = Request(scope, receive=receive)
        router = getattr(scope.get("app"), "router", None)
        endpoint, exists, methods = route_facts(router, scope)
        ip = resolve_ip_from_fastapi_request(request)
        query, body, exhausted = await self.pipeline.capture_asgi(request)
        begin = partial(self.pipeline.begin, ip=ip, path=scope.get("path", "/"), method=request.method,
            headers=environ_headers(request.headers, "HTTP/" + scope.get("http_version", "1.1")),
            query=query, body=body, exists=exists, methods=methods, endpoint=endpoint,
            country=(fact_value(self.country_lookup, ip) if self.country_lookup else get_country_for_ip(ip)) if self.pipeline.needs_country else "",
            authenticated=fact_value(self.authenticated, request) if self.authenticated else False, exhausted=exhausted)
        ctx, status, payload = await run_in_threadpool(begin) if self.cache_io else begin()
        if status:
            self.pipeline.finish(ctx, status, len(payload.encode()))
            return await Response(payload, status_code=status, media_type="application/json")(scope, request.receive, send)
        replaced = False
        started = False

        async def checked_send(message):
            nonlocal replaced, started
            if message["type"] == "http.response.start":
                if started:
                    raise RuntimeError("ASGI application started its response twice")
                started = True
                headers = dict(message.get("headers", ()))
                final_status, final_payload = self.pipeline.finish(ctx, message["status"], headers.get(b"content-length", b"-").decode("latin-1"))
                if final_payload != "null":
                    replaced = True
                    return await Response(final_payload, status_code=final_status, media_type="application/json")(scope, request.receive, send)
            if not replaced:
                await send(message)

        try:
            await self.app(scope, request.receive, checked_send)
        except Exception:
            if not started:
                self.pipeline.finish(ctx, 500)
            raise
