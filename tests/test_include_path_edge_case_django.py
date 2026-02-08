#!/usr/bin/env python3
"""
Django Unit Test for Include Path Edge Case

Test the edge case where path('school/', include('pages.urls')) 
    extracts 'school' as legitimate even though 'school' is not a Django app
"""

import os
import sys
from unittest.mock import MagicMock, patch

# Setup Django
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
os.environ.setdefault('DJANGO_SETTINGS_MODULE', 'tests.test_settings')

import django
django.setup()

from django.test import override_settings
from tests.base_test import AIWAFMiddlewareTestCase
from aiwaf.middleware import IPAndKeywordBlockMiddleware


class IncludePathEdgeCaseTestCase(AIWAFMiddlewareTestCase):
    """Validate include() prefixes don't whitelist arbitrary keywords."""
    
    def setUp(self):
        super().setUp()
        self.middleware = IPAndKeywordBlockMiddleware(self.mock_get_response)
    
    def test_include_path_edge_case(self):
        """Safe prefixes prevent blocking when include routes exist."""
        with patch("aiwaf.middleware.is_middleware_disabled", return_value=False), \
             patch("aiwaf.middleware.is_exempt", return_value=False), \
             patch("aiwaf.middleware.is_ip_exempted", return_value=False), \
             patch("aiwaf.middleware.BlacklistManager.is_blocked", return_value=False), \
             patch("aiwaf.middleware.BlacklistManager.block") as mock_block, \
             patch("aiwaf.middleware.path_exists_in_django", return_value=False):
            middleware = IPAndKeywordBlockMiddleware(self.mock_get_response)
            middleware.safe_prefixes = {"school"}
            request = self.factory.get("/school/dashboard/")
            request.META["REMOTE_ADDR"] = "203.0.113.220"
            middleware(request)
        mock_block.assert_not_called()
    
    @override_settings(AIWAF_ENABLE_KEYWORD_LEARNING=True)
    def test_middleware_behavior_with_edge_case(self):
        """If prefix not marked safe, suspicious keyword leads to block."""
        store = MagicMock()
        store.get_top_keywords.return_value = ["shellupload"]
        with patch("aiwaf.middleware.get_keyword_store", return_value=store), \
             patch("aiwaf.middleware.is_middleware_disabled", return_value=False), \
             patch("aiwaf.middleware.is_exempt", return_value=False), \
             patch("aiwaf.middleware.is_ip_exempted", return_value=False), \
             patch("aiwaf.middleware.BlacklistManager.is_blocked", side_effect=[False, True]), \
             patch("aiwaf.middleware.BlacklistManager.block") as mock_block, \
             patch("aiwaf.middleware.path_exists_in_django", return_value=False), \
             patch("aiwaf.middleware._raise_blocked") as mock_raise:
            middleware = IPAndKeywordBlockMiddleware(self.mock_get_response)
            middleware.safe_prefixes = set()
            request = self.factory.get("/school/shellupload/")
            request.META["REMOTE_ADDR"] = "203.0.113.221"
            middleware(request)
        mock_block.assert_called_once()
        args, _ = mock_raise.call_args
        self.assertIn("shellupload", args[1])
    


if __name__ == "__main__":
    import unittest
    unittest.main()
