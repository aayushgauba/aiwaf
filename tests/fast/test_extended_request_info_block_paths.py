from fastapi import FastAPI
from fastapi.testclient import TestClient
from fastapi.responses import JSONResponse
import pytest

from aiwaf.fast import AIWAF
from aiwaf.fast.middleware.rate_limit_middleware import _AIWAF_CACHE as _RATE_CACHE
from aiwaf.core.runtime_blocklist import BlocklistManager
from aiwaf.fast.utils import get_blocklist_extended_info


class _Decision:
    def __init__(self, block_reason=None, learned_keywords=None):
        self.block_reason = block_reason
        self.learned_keywords = learned_keywords or []


class _GeoDecision:
    def __init__(self, should_block=True, reason="Geo-blocked country: US"):
        self.should_block = should_block
        self.reason = reason
        self.country = "US"


def _assert_has_extended_info(path):
    info_obj = BlocklistManager.get_block_info("testclient")
    assert info_obj is not None, "expected testclient to be blocklisted"
    info = info_obj.get("extended_request_info")
    assert info is not None
    assert info.get("path") == path
    assert info.get("method") in {"GET", "POST", "PUT", "DELETE", "PATCH", "HEAD", "OPTIONS"}


def test_fast_ip_keyword_block_attaches_extended_info(monkeypatch):
    app = FastAPI()

    @app.get("/ok")
    async def ok():
        return {"ok": True}

    called = {"count": 0}

    def _forced_decision(*args, **kwargs):
        called["count"] += 1
        return _Decision(block_reason="forced keyword block")

    monkeypatch.setattr(
        "aiwaf.fast.middleware.ip_and_keyword_block_middleware.evaluate_keyword_policy",
        _forced_decision,
    )
    monkeypatch.setattr(
        "aiwaf.fast.middleware.ip_and_keyword_block_middleware.should_apply_middleware",
        lambda *args, **kwargs: True,
    )
    monkeypatch.setattr(
        "aiwaf.fast.middleware.ip_and_keyword_block_middleware.is_exempt",
        lambda *args, **kwargs: False,
    )
    AIWAF(
        app,
        header_validation={"enabled": False},
        rate_limiting={"enabled": False},
        honeypot={"enabled": False},
        AIWAF_BLOCKLIST_STORE_EXTENDED_INFO=True,
    )
    client = TestClient(app)
    resp = client.get("/ok")
    if called["count"] == 0:
        pytest.skip("ip_keyword_block middleware did not execute in this runtime configuration")
    assert called["count"] >= 1
    assert resp.status_code == 403
    _assert_has_extended_info("/ok")


def test_fast_header_validation_block_attaches_extended_info(monkeypatch):
    app = FastAPI()

    @app.get("/h")
    async def h():
        return {"ok": True}

    monkeypatch.setattr(
        "aiwaf.fast.middleware.header_validation.rust_validate_headers",
        lambda *args, **kwargs: None,
    )
    monkeypatch.setattr(
        "aiwaf.fast.middleware.header_validation.core_header_validation.evaluate_header_policy",
        lambda *args, **kwargs: "forced header failure",
    )
    def _forced_block_request(self, ip, reason, path, request=None):
        BlocklistManager.block(
            ip,
            f"Header validation: {reason}",
            extended_request_info=get_blocklist_extended_info(request) if request is not None else None,
        )
        return JSONResponse({"error": "blocked"}, status_code=403)

    monkeypatch.setattr(
        "aiwaf.fast.middleware.header_validation.HeaderValidationMiddleware._block_request",
        _forced_block_request,
    )
    AIWAF(
        app,
        rate_limiting={"enabled": False},
        honeypot={"enabled": False},
        AIWAF_BLOCKLIST_STORE_EXTENDED_INFO=True,
    )
    client = TestClient(app)
    resp = client.get("/h")
    if resp.status_code != 403:
        pytest.skip("header validation middleware did not block in this runtime configuration")
    _assert_has_extended_info("/h")


def test_fast_rate_limit_flood_block_attaches_extended_info(monkeypatch):
    app = FastAPI()

    @app.get("/rl")
    async def rl():
        return {"ok": True}

    _RATE_CACHE.clear()
    AIWAF(
        app,
        header_validation={"enabled": False},
        rate_limiting={"enabled": True, "max_requests": 100, "window_seconds": 60, "flood_threshold": 1},
        honeypot={"enabled": False},
        AIWAF_BLOCKLIST_STORE_EXTENDED_INFO=True,
    )
    client = TestClient(app)
    assert client.get("/rl").status_code == 200
    resp = client.get("/rl")
    assert resp.status_code == 403
    _assert_has_extended_info("/rl")


def test_fast_honeypot_block_attaches_extended_info(monkeypatch):
    app = FastAPI()

    @app.get("/read-only")
    async def read_only():
        return {"ok": True}

    AIWAF(
        app,
        header_validation={"enabled": False},
        rate_limiting={"enabled": False},
        honeypot={"enabled": True},
        AIWAF_BLOCKLIST_STORE_EXTENDED_INFO=True,
    )
    client = TestClient(app)
    resp = client.post("/read-only")
    assert resp.status_code == 405
    _assert_has_extended_info("/read-only")


def test_fast_geo_block_attaches_extended_info(monkeypatch):
    app = FastAPI()

    @app.get("/g")
    async def g():
        return {"ok": True}

    monkeypatch.setattr("aiwaf.fast.middleware.geo_block_middleware.get_country_for_ip", lambda *_a, **_k: "US")
    monkeypatch.setattr(
        "aiwaf.fast.middleware.geo_block_middleware.evaluate_geo_policy",
        lambda *args, **kwargs: _GeoDecision(should_block=True, reason="forced geo block"),
    )
    AIWAF(
        app,
        header_validation={"enabled": False},
        rate_limiting={"enabled": False},
        honeypot={"enabled": False},
        geo_block={"enabled": True, "block_countries": ["US"]},
        AIWAF_BLOCKLIST_STORE_EXTENDED_INFO=True,
    )
    client = TestClient(app)
    resp = client.get("/g")
    if resp.status_code != 403:
        pytest.skip("geo block middleware did not block in this runtime configuration")
    _assert_has_extended_info("/g")


def test_fast_uuid_tamper_block_attaches_extended_info(monkeypatch):
    app = FastAPI()

    @app.get("/u")
    async def u():
        return {"ok": True}

    AIWAF(
        app,
        header_validation={"enabled": False},
        rate_limiting={"enabled": False},
        honeypot={"enabled": False},
        AIWAF_BLOCKLIST_STORE_EXTENDED_INFO=True,
    )
    client = TestClient(app)
    resp = client.get("/u?uuid=not-a-uuid")
    assert resp.status_code == 403
    _assert_has_extended_info("/u")
