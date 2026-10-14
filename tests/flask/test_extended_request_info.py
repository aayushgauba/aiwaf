from flask import Flask

from aiwaf.flask import blocklist_manager as bm


def test_block_without_request_context_does_not_attach_info(monkeypatch):
    captured = {}

    def fake_add(ip, reason=None, extended_request_info=None):
        captured["ip"] = ip
        captured["reason"] = reason
        captured["extended_request_info"] = extended_request_info

    monkeypatch.setattr(bm, "add_ip_blocklist", fake_add)
    bm.BlocklistManager.block("10.0.0.1", "test reason")

    assert captured["ip"] == "10.0.0.1"
    assert captured["reason"] == "test reason"
    assert captured["extended_request_info"] is None


def test_block_with_request_context_attaches_extended_info(monkeypatch):
    app = Flask(__name__)
    app.config["AIWAF_CAPTURE_EXTENDED_REQUEST_INFO"] = True
    app.config["AIWAF_EXTENDED_REQUEST_INFO_HEADERS"] = ["User-Agent", "Authorization"]
    app.config["AIWAF_EXTENDED_REQUEST_INFO_REDACT_HEADERS"] = ["Authorization"]
    app.config["AIWAF_EXTENDED_REQUEST_INFO_MAX_BYTES"] = 8192

    captured = {}

    def fake_add(ip, reason=None, extended_request_info=None):
        captured["extended_request_info"] = extended_request_info

    monkeypatch.setattr(bm, "add_ip_blocklist", fake_add)

    with app.test_request_context(
        "/login?x=1",
        method="POST",
        base_url="https://example.com",
        headers={
            "User-Agent": "pytest-agent",
            "Authorization": "Bearer secret",
        },
    ):
        bm.BlocklistManager.block("10.0.0.2", "bad")

    info = captured["extended_request_info"]
    assert info is not None
    assert info["path"] == "/login"
    assert info["query"] == "x=1"
    assert info["method"] == "POST"
    assert info["headers"]["User-Agent"] == "pytest-agent"
    assert info["headers"]["Authorization"] == "[REDACTED]"


def test_block_with_request_context_disabled_capture(monkeypatch):
    app = Flask(__name__)
    app.config["AIWAF_CAPTURE_EXTENDED_REQUEST_INFO"] = False

    captured = {}

    def fake_add(ip, reason=None, extended_request_info=None):
        captured["extended_request_info"] = extended_request_info

    monkeypatch.setattr(bm, "add_ip_blocklist", fake_add)

    with app.test_request_context("/health", method="GET"):
        bm.BlocklistManager.block("10.0.0.3", "blocked")

    assert captured["extended_request_info"] is None


def test_block_with_request_context_size_limit_truncates(monkeypatch):
    app = Flask(__name__)
    app.config["AIWAF_CAPTURE_EXTENDED_REQUEST_INFO"] = True
    app.config["AIWAF_EXTENDED_REQUEST_INFO_HEADERS"] = ["User-Agent", "Authorization"]
    app.config["AIWAF_EXTENDED_REQUEST_INFO_REDACT_HEADERS"] = ["Authorization"]
    app.config["AIWAF_EXTENDED_REQUEST_INFO_MAX_BYTES"] = 64

    captured = {}

    def fake_add(ip, reason=None, extended_request_info=None):
        captured["extended_request_info"] = extended_request_info

    monkeypatch.setattr(bm, "add_ip_blocklist", fake_add)

    with app.test_request_context(
        "/very/long/path/for/testing/size/limit",
        method="POST",
        base_url="https://example.com",
        query_string={"payload": "x" * 2048},
        headers={
            "User-Agent": "agent-" + ("y" * 2048),
            "Authorization": "Bearer secret",
        },
    ):
        bm.BlocklistManager.block("10.0.0.4", "blocked")

    info = captured["extended_request_info"]
    assert info is not None
    assert info["path"].startswith("/")
    assert info["method"] == "POST"
    assert info["host"] == "example.com"
    assert info.get("truncated") is True
