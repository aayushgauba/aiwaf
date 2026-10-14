from flask import Flask

from aiwaf.flask import blocklist_manager as bm
from aiwaf.flask.geo_block_middleware import GeoBlockMiddleware
from aiwaf.flask.header_validation_middleware import HeaderValidationMiddleware
from aiwaf.flask.honeypot_timing_middleware import HoneypotTimingMiddleware
from aiwaf.flask.ip_and_keyword_block_middleware import IPAndKeywordBlockMiddleware
from aiwaf.flask.rate_limit_middleware import RateLimitMiddleware, _aiwaf_cache as _rate_cache
from aiwaf.flask.uuid_tamper_middleware import UUIDTamperMiddleware


class _Decision:
    def __init__(self, block_reason=None, learned_keywords=None):
        self.block_reason = block_reason
        self.learned_keywords = learned_keywords or []


def _make_app():
    app = Flask(__name__)
    app.config["TESTING"] = True
    app.config["AIWAF_CAPTURE_EXTENDED_REQUEST_INFO"] = True
    return app


def _capture_blocks(monkeypatch):
    captured = []

    def fake_add(ip, reason=None, extended_request_info=None):
        captured.append(
            {
                "ip": ip,
                "reason": reason,
                "extended_request_info": extended_request_info,
            }
        )

    monkeypatch.setattr(bm, "add_ip_blocklist", fake_add)
    return captured


def _assert_has_extended_info(captured, path):
    assert captured, "expected a blocklist block call"
    info = captured[-1]["extended_request_info"]
    assert info is not None
    assert info.get("path") == path
    assert info.get("method") in {"GET", "POST", "PUT", "DELETE", "PATCH", "HEAD", "OPTIONS"}


def test_ip_keyword_block_attaches_extended_info(monkeypatch):
    app = _make_app()

    @app.route("/ok")
    def ok():
        return "ok"

    captured = _capture_blocks(monkeypatch)
    IPAndKeywordBlockMiddleware(app)
    monkeypatch.setattr(
        "aiwaf.flask.ip_and_keyword_block_middleware.evaluate_keyword_policy",
        lambda *args, **kwargs: _Decision(block_reason="forced keyword block"),
    )

    with app.test_client() as client:
        resp = client.get("/wp-admin")
        assert resp.status_code == 403

    _assert_has_extended_info(captured, "/wp-admin")


def test_header_validation_block_attaches_extended_info(monkeypatch):
    app = _make_app()
    captured = _capture_blocks(monkeypatch)
    monkeypatch.setattr(
        "aiwaf.flask.header_validation_middleware.rust_backend.evaluate_headers_full_default",
        lambda *args, **kwargs: (False, None),
    )
    HeaderValidationMiddleware(app)

    @app.route("/h")
    def h():
        return "ok"

    monkeypatch.setattr(
        "aiwaf.flask.header_validation_middleware.header_validation.evaluate_header_policy",
        lambda *args, **kwargs: "forced header failure",
    )

    with app.test_client() as client:
        resp = client.get("/h")
        assert resp.status_code == 403

    _assert_has_extended_info(captured, "/h")


def test_rate_limit_flood_block_attaches_extended_info(monkeypatch):
    app = _make_app()
    app.config["AIWAF_RATE_WINDOW"] = 60
    app.config["AIWAF_RATE_MAX"] = 100
    app.config["AIWAF_RATE_FLOOD"] = 1
    _rate_cache.clear()
    captured = _capture_blocks(monkeypatch)
    RateLimitMiddleware(app)

    @app.route("/rl")
    def rl():
        return "ok"

    with app.test_client() as client:
        assert client.get("/rl").status_code == 200
        resp = client.get("/rl")
        assert resp.status_code == 403

    _assert_has_extended_info(captured, "/rl")


def test_honeypot_block_attaches_extended_info(monkeypatch):
    app = _make_app()
    captured = _capture_blocks(monkeypatch)
    HoneypotTimingMiddleware(app)

    @app.route("/read-only", methods=["GET"])
    def read_only():
        return "ok"

    with app.test_client() as client:
        resp = client.post("/read-only")
        assert resp.status_code == 405

    _assert_has_extended_info(captured, "/read-only")


def test_geo_block_attaches_extended_info(monkeypatch):
    app = _make_app()
    app.config["AIWAF_GEO_BLOCK_ENABLED"] = True
    app.config["AIWAF_GEO_BLOCK_COUNTRIES"] = ["US"]
    captured = _capture_blocks(monkeypatch)
    GeoBlockMiddleware(app)

    @app.route("/g")
    def g():
        return "ok"

    monkeypatch.setattr("aiwaf.flask.geo_block_middleware.get_country_for_ip", lambda *_args, **_kwargs: "US")

    with app.test_client() as client:
        resp = client.get("/g")
        assert resp.status_code == 403

    _assert_has_extended_info(captured, "/g")


def test_uuid_tamper_block_attaches_extended_info(monkeypatch):
    app = _make_app()
    captured = _capture_blocks(monkeypatch)
    UUIDTamperMiddleware(app)

    @app.route("/u")
    def u():
        return "ok"

    with app.test_client() as client:
        resp = client.get("/u?uuid=not-a-uuid")
        assert resp.status_code == 403

    _assert_has_extended_info(captured, "/u")
