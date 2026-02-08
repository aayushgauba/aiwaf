#!/usr/bin/env python3
"""
Django Unit Test for Edge Case Fix Demo

Test to demonstrate the fix for the edge case where path('school/', include('pages.urls'))
would incorrectly mark 'school' as a legitimate keyword even though it's not a Django app.
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
from aiwaf.middleware import IPAndKeywordBlockMiddleware, path_exists_in_django


class EdgeCaseFixDemoTestCase(AIWAFMiddlewareTestCase):
    """Ensure include prefixes like 'school/' are not treated as legitimate keywords."""
    
    def setUp(self):
        super().setUp()
        self.middleware = IPAndKeywordBlockMiddleware(self.mock_get_response)
    
    def test_url_pattern_extraction_does_not_mark_school_prefix(self):
        """path_exists_in_django stays False for school include edge case."""
        self.assertFalse(path_exists_in_django("/school/"))
        self.assertFalse(path_exists_in_django("/school/grades/"))
    
    @override_settings(AIWAF_ENABLE_KEYWORD_LEARNING=True)
    def test_malicious_request_scenarios_block_unknown_keyword(self):
        """Nonexistent school prefix with suspicious keyword triggers blocking."""
        store = MagicMock()
        store.get_top_keywords.return_value = []
        store.add_keyword = MagicMock()
        def fake_is_malicious(_self, _request, segment):
            return "evil" in segment

        with patch("aiwaf.middleware.get_keyword_store", return_value=store), \
             patch("aiwaf.middleware.is_middleware_disabled", return_value=False), \
             patch("aiwaf.middleware.is_exempt", return_value=False), \
             patch("aiwaf.middleware.is_ip_exempted", return_value=False), \
             patch("aiwaf.middleware.BlacklistManager.is_blocked", return_value=False), \
             patch("aiwaf.middleware.BlacklistManager.block") as mock_block, \
             patch("aiwaf.middleware._get_blacklist_extended_info", return_value=None), \
             patch("aiwaf.middleware.path_exists_in_django", return_value=False), \
             patch("aiwaf.middleware._raise_blocked"), \
             patch.object(IPAndKeywordBlockMiddleware, "_is_malicious_context", fake_is_malicious):
            middleware = IPAndKeywordBlockMiddleware(self.mock_get_response)
            middleware.safe_prefixes = set()
            # Avoid STATIC_KW collisions like "shell" causing extra blocks.
            request = self.factory.get("/school/evilzebra.php")
            request.META["REMOTE_ADDR"] = "203.0.113.210"
            middleware(request)
        store.add_keyword.assert_called_with("evilzebra")
        reasons = [c.args[1] for c in mock_block.call_args_list]
        self.assertTrue(any("evil" in r for r in reasons), reasons)
    


if __name__ == "__main__":
    import unittest
    unittest.main()
