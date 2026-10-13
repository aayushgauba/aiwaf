"""Explicit Rust-owned CSV pipeline; no automatic fallback or legacy config mixing."""
from __future__ import annotations

import importlib
import json
import inspect
import time
from dataclasses import dataclass
from .sql_injection import inspect_wsgi_request, inspect_asgi_request
from .storage_ops import now_iso

STAGES = frozenset({"geo_block", "ip_keyword_block", "rate_limit", "ai_anomaly",
                    "honeypot", "uuid_tamper", "header_validation", "logging"})


@dataclass(frozen=True)
class _BufferPolicy:
    """Only the transport buffer contract; it performs no Python SQL decisions."""
    mode: str
    max_bytes: int

    @staticmethod
    def enforce(finding):
        return finding


def validate_fact_callback(callback):
    if callback is not None and (not callable(callback) or inspect.iscoroutinefunction(callback)):
        raise TypeError("Pipeline fact callbacks must be synchronous callables")


def fact_value(callback, value):
    result = callback(value)
    if inspect.isawaitable(result):
        if inspect.iscoroutine(result):
            result.close()
        raise TypeError("Pipeline fact callbacks must return synchronous values")
    return result


class CSVPipeline:
    """Immutable profile plus Rust-owned state. Install instead of the legacy chain.

    ``config`` uses the native profile's lowercase keys; it does not implicitly
    consume framework settings, custom stores or legacy middleware callbacks.
    A missing/outdated native extension is a startup error, never a Python fallback.
    """
    def __init__(self, config=None, *, model=None):
        config = dict(config or {})
        self.profile = config
        self.needs_country = "geo_block" in config.get("enabled", STAGES)
        try:
            factory = importlib.import_module("aiwaf_rust").NativeCSVPipeline
        except (ImportError, AttributeError) as error:
            raise RuntimeError("The CSV pipeline requires aiwaf-rust with NativeCSVPipeline support") from error
        self.native = factory(json.dumps(config, allow_nan=False))
        self.policy = _BufferPolicy(config.get("sql_mode", "block"), config.get("max_bytes", 65536))
        if model is not None:
            self.native.set_model(model)

    def begin(self, *, ip, path, method, headers, query, body, exists, methods,
              authenticated=False, endpoint=None, country="", exhausted=False):
        disabled, exempt = endpoint_exemptions(endpoint)
        headers = dict(headers)
        headers["AIWAF_COUNTRY"] = country or ""
        now = time.time()
        return self.native.begin(ip or "unknown", path, method, headers, query or b"", body or b"",
            bool(exists), "GET" in methods, "POST" in methods, method.upper() in methods,
            bool(authenticated), disabled, exempt, now, now_iso(), bool(exhausted))

    def finish(self, context, status, content_length="-"):
        return self.native.finish(context, int(status), time.time(), str(content_length), True)

    def capture_wsgi(self, request, *, django=False):
        captured = [b"", None]

        def capture(query, body):
            captured[:] = [query, body]
            return None

        finding = inspect_wsgi_request(request, self.policy, django=django, evaluator=capture)
        query = captured[0]
        if isinstance(query, str):
            query = query.encode("utf-8", errors="replace")
        return query, captured[1], bool(finding)

    async def capture_asgi(self, request):
        captured = [request.scope.get("query_string", b""), None]

        def capture(query, body):
            captured[:] = [query, body]
            return None

        finding = await inspect_asgi_request(request, self.policy, evaluator=capture)
        return captured[0], captured[1], bool(finding)


def endpoint_exemptions(endpoint):
    """Extract decorator facts once; native enforcement owns global exemptions."""
    required = set(getattr(endpoint, "_aiwaf_required_middlewares", ()) or ())
    full = bool(getattr(endpoint, "_aiwaf_exempt", False) or getattr(endpoint, "aiwaf_exempt", False))
    disabled = set(STAGES if full else (getattr(endpoint, "_aiwaf_exempt_middlewares", ()) or ()))
    return disabled - required, False


def environ_headers(headers, protocol="HTTP/1.1"):
    result = {("CONTENT_TYPE" if k.lower() == "content-type" else
               "CONTENT_LENGTH" if k.lower() == "content-length" else
               "HTTP_" + k.upper().replace("-", "_")): str(v) for k, v in headers.items()}
    result["SERVER_PROTOCOL"] = protocol
    return result
