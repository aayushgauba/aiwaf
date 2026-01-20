#!/usr/bin/env python3
"""
Django Unit Test for 404 Only Learning

Test to demonstrate why learning should only happen from 404s, not other error codes like 403.
"""

import os
import sys
import time
from unittest.mock import patch, MagicMock

# Setup Django
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
os.environ.setdefault('DJANGO_SETTINGS_MODULE', 'tests.test_settings')

import django
django.setup()

from tests.base_test import AIWAFTestCase


class Only404LearningTestCase(AIWAFTestCase):
    """Test 404 Only Learning functionality"""
    
    def setUp(self):
        super().setUp()
        from django.core.cache import cache
        cache.clear()

    @patch("aiwaf.middleware.path_exists_in_django", return_value=True)
    @patch("aiwaf.middleware.BlacklistManager.block")
    @patch("aiwaf.middleware.BlacklistManager.is_blocked", return_value=False)
    @patch("aiwaf.middleware.NUMPY_AVAILABLE", True)
    def test_403s_do_not_trigger_ai_blocking(self, _mock_blocked, mock_block, _mock_path_exists):
        """403s should not be treated like 404s for AI blocking decisions."""
        from django.core.cache import cache
        from django.http import HttpResponse
        from django.test import override_settings
        from aiwaf.middleware import AIAnomalyMiddleware

        class DummyArray:
            def reshape(self, *_args, **_kwargs):
                return self

        class DummyNumpy:
            def array(self, _feats, dtype=float):
                return DummyArray()

        ip = "10.0.0.1"
        request = self.create_request(
            "/api/health/",
            headers={"REMOTE_ADDR": ip}
        )

        # Seed recent data with 403s only (no 404s)
        now = time.time()
        data = [
            (now - 2, "/api/health/", 403, 0.05),
            (now - 1, "/api/health/", 403, 0.04),
        ]
        cache.set(f"aiwaf:{ip}", data, timeout=60)

        mock_model = MagicMock()
        mock_model.predict.return_value = [-1]

        with patch("aiwaf.middleware.MODEL", mock_model), patch("aiwaf.middleware.np", DummyNumpy()):
            with override_settings(AIWAF_MIN_AI_LOGS=0):
                middleware = AIAnomalyMiddleware(MagicMock())
                response = middleware.process_response(request, HttpResponse(status=200))

        self.assertEqual(response.status_code, 200)
        mock_block.assert_not_called()

    @patch("aiwaf.middleware.path_exists_in_django", return_value=True)
    @patch("aiwaf.middleware.BlacklistManager.block")
    @patch("aiwaf.middleware.BlacklistManager.is_blocked", return_value=False)
    @patch("aiwaf.middleware.NUMPY_AVAILABLE", True)
    def test_burst_without_404s_does_not_block(self, _mock_blocked, mock_block, _mock_path_exists):
        """Pure burst traffic without 404s/keywords should not be blocked."""
        from django.core.cache import cache
        from django.http import HttpResponse
        from django.test import override_settings
        from aiwaf.middleware import AIAnomalyMiddleware

        class DummyArray:
            def reshape(self, *_args, **_kwargs):
                return self

        class DummyNumpy:
            def array(self, _feats, dtype=float):
                return DummyArray()

        ip = "10.0.0.2"
        request = self.create_request(
            "/api/poll/",
            headers={"REMOTE_ADDR": ip}
        )

        # Seed recent data with only 200s (no 404s/keywords), but bursty
        now = time.time()
        data = [(now - (i * 0.5), "/api/poll/", 200, 0.02) for i in range(30)]
        cache.set(f"aiwaf:{ip}", data, timeout=60)

        mock_model = MagicMock()
        mock_model.predict.return_value = [-1]

        with patch("aiwaf.middleware.MODEL", mock_model), patch("aiwaf.middleware.np", DummyNumpy()):
            with override_settings(AIWAF_MIN_AI_LOGS=0):
                middleware = AIAnomalyMiddleware(MagicMock())
                response = middleware.process_response(request, HttpResponse(status=200))

        self.assertEqual(response.status_code, 200)
        mock_block.assert_not_called()



if __name__ == "__main__":
    import unittest
    unittest.main()
