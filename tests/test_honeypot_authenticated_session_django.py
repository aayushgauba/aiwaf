"""Tests for HoneypotTimingMiddleware authenticated session exemptions."""

import os
import sys
import time
from types import SimpleNamespace
from unittest.mock import patch


sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
os.environ.setdefault('DJANGO_SETTINGS_MODULE', 'tests.test_settings')

import django  # noqa: E402
django.setup()

from django.core.cache import cache  # noqa: E402

from tests.base_test import AIWAFMiddlewareTestCase  # noqa: E402
from aiwaf.middleware import HoneypotTimingMiddleware  # noqa: E402


class HoneypotAuthenticatedSessionTestCase(AIWAFMiddlewareTestCase):
    """Ensure authenticated sessions bypass honeypot timing enforcement."""

    def setUp(self):
        super().setUp()
        cache.clear()

    @patch('aiwaf.middleware.BlacklistManager.block')
    @patch('aiwaf.middleware.BlacklistManager.is_blocked', return_value=False)
    def test_authenticated_session_skips_timing(self, mock_is_blocked, mock_block):
        cache.set('honeypot_get:127.0.0.1', time.time(), timeout=300)

        request = self.create_request('/home/', method='POST')
        request.META['REMOTE_ADDR'] = '127.0.0.1'
        request.user = SimpleNamespace(is_authenticated=True)

        class DummySession(dict):
            session_key = 'dummy'

        request.session = DummySession({'_auth_user_id': '42'})

        middleware = HoneypotTimingMiddleware(self.mock_get_response)

        response = middleware.process_request(request)

        self.assertIsNone(response)
        mock_block.assert_not_called()
        mock_is_blocked.assert_not_called()


if __name__ == '__main__':  # pragma: no cover
    import unittest

    unittest.main()
