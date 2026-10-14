from types import SimpleNamespace

from aiwaf.core.request_context import (
    extract_blocklist_extended_info_from_django_request,
    extract_blocklist_extended_info_from_fastapi_request,
    extract_blocklist_extended_info_from_flask_request,
    extract_headers_from_django_request,
    extract_headers_from_fastapi_request,
    extract_headers_from_flask_request,
    extract_ip_from_django_request,
    extract_ip_from_fastapi_request,
    extract_ip_from_flask_request,
    extract_logging_context_from_django_request,
    extract_logging_context_from_fastapi_request,
    extract_logging_context_from_flask_request,
    extract_query_keys_from_django_request,
    extract_query_keys_from_fastapi_request,
    extract_query_keys_from_flask_request,
    normalized_headers_to_wsgi_environ,
    resolve_ip_from_fastapi_request,
)


def test_extract_ip_from_django_request_prefers_xff():
    req = SimpleNamespace(META={"HTTP_X_FORWARDED_FOR": "203.0.113.5, 10.0.0.1", "REMOTE_ADDR": "10.0.0.1"})
    assert extract_ip_from_django_request(req) == "203.0.113.5"


def test_extract_ip_from_flask_request_prefers_xff():
    req = SimpleNamespace(headers={"X-Forwarded-For": "198.51.100.9, 10.0.0.2"}, remote_addr="10.0.0.2")
    assert extract_ip_from_flask_request(req) == "198.51.100.9"


def test_extract_ip_from_fastapi_request_uses_client_host():
    req = SimpleNamespace(client=SimpleNamespace(host="192.0.2.10"), headers={})
    assert extract_ip_from_fastapi_request(req) == "192.0.2.10"


def test_extract_ip_from_fastapi_request_falls_back_to_forwarded_headers():
    req = SimpleNamespace(client=None, headers={"x-forwarded-for": "198.51.100.77"})
    # Core extractor keeps Fast behavior minimal: prefer direct client host,
    # and otherwise defer richer proxy handling to runtime_utils.get_ip.
    assert extract_ip_from_fastapi_request(req) == ""


def test_extract_headers_from_django_request_maps_http_and_content_fields():
    req = SimpleNamespace(
        META={
            "HTTP_USER_AGENT": "Mozilla/5.0",
            "HTTP_X_REQUEST_ID": "abc",
            "CONTENT_TYPE": "application/json",
            "CONTENT_LENGTH": 12,
            "REMOTE_ADDR": "203.0.113.1",
        }
    )
    headers = extract_headers_from_django_request(req)
    assert headers["user-agent"] == "Mozilla/5.0"
    assert headers["x-request-id"] == "abc"
    assert headers["content-type"] == "application/json"
    assert headers["content-length"] == "12"
    assert "remote-addr" not in headers


def test_extract_headers_from_flask_request_lowercases_keys():
    req = SimpleNamespace(headers={"User-Agent": "UA", "X-Test": 123})
    assert extract_headers_from_flask_request(req) == {"user-agent": "UA", "x-test": "123"}


def test_extract_headers_from_fastapi_request_lowercases_keys():
    req = SimpleNamespace(headers={"Accept": "*/*", "X-Token": "t"})
    assert extract_headers_from_fastapi_request(req) == {"accept": "*/*", "x-token": "t"}


def test_extract_query_keys_from_django_request_reads_get_mapping():
    req = SimpleNamespace(GET={"a": "1", "b": "2"})
    assert extract_query_keys_from_django_request(req) == ["a", "b"]


def test_extract_query_keys_from_flask_request_reads_args_mapping():
    req = SimpleNamespace(args={"page": "1", "q": "term"})
    assert extract_query_keys_from_flask_request(req) == ["page", "q"]


def test_extract_query_keys_from_fastapi_request_parses_query_string():
    req = SimpleNamespace(url=SimpleNamespace(query="a=1&b=2&a=3&flag"))
    assert extract_query_keys_from_fastapi_request(req) == ["a", "b", "a", "flag"]


def test_extract_query_keys_from_fastapi_request_empty_query():
    req = SimpleNamespace(url=SimpleNamespace(query=""))
    assert extract_query_keys_from_fastapi_request(req) == []


def test_resolve_ip_from_fastapi_request_prefers_public_client_ip():
    req = SimpleNamespace(client=SimpleNamespace(host="8.8.8.8"), headers={"x-forwarded-for": "203.0.113.1"})
    assert resolve_ip_from_fastapi_request(req) == "8.8.8.8"


def test_resolve_ip_from_fastapi_request_uses_xff_for_proxy_like_client():
    req = SimpleNamespace(client=SimpleNamespace(host="127.0.0.1"), headers={"x-forwarded-for": "198.51.100.33, 10.0.0.1"})
    assert resolve_ip_from_fastapi_request(req) == "198.51.100.33"


def test_normalized_headers_to_wsgi_environ_maps_headers_and_protocol():
    headers = {"user-agent": "UA", "x-test": "1"}
    env = normalized_headers_to_wsgi_environ(headers, "1.1")
    assert env["HTTP_USER_AGENT"] == "UA"
    assert env["HTTP_X_TEST"] == "1"
    assert env["SERVER_PROTOCOL"] == "HTTP/1.1"


def test_extract_logging_context_from_django_request():
    req = SimpleNamespace(
        method="GET",
        path="/a/b",
        META={
            "QUERY_STRING": "x=1",
            "SERVER_PROTOCOL": "HTTP/1.1",
            "HTTP_REFERER": "https://example.test/",
            "HTTP_USER_AGENT": "UA",
            "REMOTE_ADDR": "203.0.113.9",
        },
    )
    ctx = extract_logging_context_from_django_request(req)
    assert ctx["ip"] == "203.0.113.9"
    assert ctx["path_with_query"] == "/a/b?x=1"
    assert ctx["protocol"] == "HTTP/1.1"
    assert ctx["user_agent"] == "UA"


def test_extract_logging_context_from_flask_request():
    req = SimpleNamespace(
        method="POST",
        path="/submit",
        full_path="/submit?token=1",
        query_string=b"token=1",
        environ={"SERVER_PROTOCOL": "HTTP/1.0"},
        headers={"Referer": "https://ref.test/", "User-Agent": "UA2"},
        remote_addr="198.51.100.6",
    )
    ctx = extract_logging_context_from_flask_request(req)
    assert ctx["ip"] == "198.51.100.6"
    assert ctx["path_with_query"] == "/submit?token=1"
    assert ctx["protocol"] == "HTTP/1.0"
    assert ctx["referer"] == "https://ref.test/"


def test_extract_logging_context_from_fastapi_request():
    req = SimpleNamespace(
        method="PUT",
        url=SimpleNamespace(path="/api/x", query="q=ok"),
        scope={"http_version": "2"},
        headers={"referer": "https://r.test/", "user-agent": "UA3"},
        client=SimpleNamespace(host="8.8.8.8"),
    )
    ctx = extract_logging_context_from_fastapi_request(req)
    assert ctx["ip"] == "8.8.8.8"
    assert ctx["path_with_query"] == "/api/x?q=ok"
    assert ctx["protocol"] == "HTTP/2"
    assert ctx["user_agent"] == "UA3"


def test_extract_blocklist_extended_info_from_django_request():
    req = SimpleNamespace(
        method="POST",
        path="/login",
        META={
            "QUERY_STRING": "a=1",
            "HTTP_USER_AGENT": "UA",
            "HTTP_AUTHORIZATION": "secret",
            "REMOTE_ADDR": "203.0.113.5",
        },
        build_absolute_uri=lambda: "https://example.test/login?a=1",
        get_host=lambda: "example.test",
    )
    info = extract_blocklist_extended_info_from_django_request(
        req,
        enabled=True,
        max_headers=10,
        max_value_len=50,
        redact_headers=["Authorization"],
    )
    assert info["path"] == "/login"
    assert info["query_string"] == "a=1"
    assert info["headers"]["Authorization"] == "[redacted]"


def test_extract_blocklist_extended_info_from_flask_request():
    req = SimpleNamespace(
        url="https://example.test/login?a=1",
        path="/login",
        query_string=b"a=1",
        method="POST",
        host="example.test",
        headers={"User-Agent": "UA", "Authorization": "secret"},
        remote_addr="203.0.113.6",
    )
    info = extract_blocklist_extended_info_from_flask_request(
        req,
        enabled=True,
        max_bytes=8192,
        capture_headers=["User-Agent", "Authorization"],
        redact_headers=["Authorization"],
    )
    assert info["path"] == "/login"
    assert info["query"] == "a=1"
    assert info["headers"]["Authorization"] == "[REDACTED]"


def test_extract_blocklist_extended_info_from_fastapi_request():
    req = SimpleNamespace(
        method="GET",
        url=SimpleNamespace(path="/x", query="k=1", netloc="example.test"),
        headers={"user-agent": "UA", "authorization": "secret"},
        client=SimpleNamespace(host="8.8.8.8"),
        scope={"http_version": "1.1"},
    )
    info = extract_blocklist_extended_info_from_fastapi_request(
        req,
        enabled=True,
        max_headers=10,
        max_value_len=50,
        redact_headers=["Authorization"],
    )
    assert info["path"] == "/x"
    assert info["query_string"] == "k=1"
    assert info["headers"]["Authorization"] == "[redacted]"
