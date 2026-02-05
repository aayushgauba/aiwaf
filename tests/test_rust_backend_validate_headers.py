#!/usr/bin/env python3
"""Tests for rust_backend.validate_headers dispatch behavior."""

import unittest
from unittest.mock import MagicMock

import aiwaf.rust_backend as rb


@unittest.skipUnless(rb.rust_available(), "aiwaf_rust extension not available")
def test_validate_headers_uses_config_when_available():
    print("Rust test running: validate_headers_with_config path")
    original = rb.aiwaf_rust
    try:
        stub = MagicMock()
        stub.validate_headers_with_config.return_value = "ok"
        rb.aiwaf_rust = stub

        result = rb.validate_headers({"HTTP_USER_AGENT": "x"}, ["HTTP_USER_AGENT"], 3)
        assert result == "ok"
        stub.validate_headers_with_config.assert_called_once()
    finally:
        rb.aiwaf_rust = original


@unittest.skipUnless(rb.rust_available(), "aiwaf_rust extension not available")
def test_validate_headers_falls_back_without_config():
    original = rb.aiwaf_rust
    try:
        class Stub:
            def validate_headers(self, headers):
                return "fallback"
        rb.aiwaf_rust = Stub()

        result = rb.validate_headers({"HTTP_USER_AGENT": "x"}, ["HTTP_USER_AGENT"], 3)
        assert result == "fallback"
    finally:
        rb.aiwaf_rust = original
