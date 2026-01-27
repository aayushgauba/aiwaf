#!/usr/bin/env python3
"""
Django Unit Tests for UUIDTamperMiddleware
"""

import os
import sys
from types import SimpleNamespace
from unittest.mock import MagicMock, patch

# Setup Django
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
os.environ.setdefault("DJANGO_SETTINGS_MODULE", "tests.test_settings")

import django
django.setup()

from django.db import models
from django.core.exceptions import PermissionDenied
from tests.base_test import AIWAFTestCase


class UUIDTamperMiddlewareTestCase(AIWAFTestCase):
    def setUp(self):
        super().setUp()
        from aiwaf import middleware as mw
        mw._UUID_MODEL_CACHE.clear()

    def _fake_model(self, pk_field, other_fields=None, exists=False):
        if other_fields is None:
            other_fields = []
        meta = SimpleNamespace(pk=pk_field, fields=[pk_field] + other_fields)
        model = MagicMock()
        model._meta = meta
        queryset = MagicMock()
        queryset.exists.return_value = exists
        model.objects.filter.return_value = queryset
        return model

    def _run_middleware(self, view_module, uuid_value, app_models, is_blocked=False):
        from aiwaf.middleware import UUIDTamperMiddleware

        request = self.create_request("/items/{}".format(uuid_value))
        view_func = MagicMock()
        view_func.__module__ = view_module

        with patch("aiwaf.middleware.apps.get_app_config") as mock_get_app:
            mock_app_cfg = MagicMock()
            mock_app_cfg.get_models.return_value = app_models
            mock_get_app.return_value = mock_app_cfg
            with patch("aiwaf.middleware.is_middleware_disabled", return_value=False), \
                 patch("aiwaf.middleware.is_exempt", return_value=False), \
                 patch("aiwaf.middleware.is_ip_exempted", return_value=False), \
                 patch("aiwaf.middleware.get_ip", return_value="10.0.0.1"), \
                 patch("aiwaf.middleware.BlacklistManager.block") as mock_block, \
                 patch("aiwaf.middleware.BlacklistManager.is_blocked", return_value=is_blocked):
                middleware = UUIDTamperMiddleware(MagicMock())
                try:
                    response = middleware.process_view(request, view_func, [], {"uuid": uuid_value})
                    captured_exc = None
                except Exception as exc:
                    response = None
                    captured_exc = exc
        return response, mock_block, captured_exc

    def test_no_uuid_models_is_noop(self):
        pk = models.AutoField(primary_key=True)
        model = self._fake_model(pk, other_fields=[], exists=False)
        response, mock_block, captured_exc = self._run_middleware(
            "myapp.views",
            "9b4185fe-7c5d-4c6a-bd25-b79a4e4c0f7b",
            [model],
        )
        self.assertIsNone(response)
        self.assertIsNone(captured_exc)
        mock_block.assert_not_called()

    def test_unique_uuid_field_allows_match(self):
        pk = models.AutoField(primary_key=True)
        uuid_field = models.UUIDField(unique=True)
        uuid_field.name = "uuid"
        model = self._fake_model(pk, other_fields=[uuid_field], exists=True)
        response, mock_block, captured_exc = self._run_middleware(
            "shop.views",
            "3f8b8fd0-ec0b-4d0a-bc0e-90ec0fd6f3ea",
            [model],
        )
        self.assertIsNone(response)
        self.assertIsNone(captured_exc)
        mock_block.assert_not_called()

    def test_uuid_tamper_blocks_when_no_match(self):
        pk = models.UUIDField(primary_key=True)
        model = self._fake_model(pk, other_fields=[], exists=False)
        response, mock_block, captured_exc = self._run_middleware(
            "accounts.views",
            "0ad0b8a7-7b95-4a7a-9ea5-9b5a5b07c2ef",
            [model],
            is_blocked=True,
        )
        self.assertIsNone(response)
        self.assertIsInstance(captured_exc, PermissionDenied)
        mock_block.assert_called_once()


if __name__ == "__main__":
    import unittest
    unittest.main()
