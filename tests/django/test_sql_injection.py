import json
import os
import unittest
from unittest.mock import MagicMock, patch
os.environ.setdefault('DJANGO_SETTINGS_MODULE', 'tests.django.test_settings')
import django
django.setup()
from django.test import RequestFactory, override_settings
from django.http import JsonResponse
from aiwaf.django.middleware import IPAndKeywordBlockMiddleware
from tests.sql_policy.cases import FrameworkCases, wire_body, echo_body


class DjangoPolicyTests(FrameworkCases, unittest.TestCase):
    def send(self, payload, mode='block', max_bytes=65536, exempt=False, query='', content_type='application/json'):
        module = 'aiwaf.django.middleware.'
        store = MagicMock(); store.get_top_keywords.return_value = []
        def handler(request):
            return JsonResponse(echo_body(request.body, request.content_type), status=401)
        with override_settings(AIWAF_SQL_INJECTION_MODE=mode, AIWAF_PAYLOAD_MAX_BYTES=max_bytes), \
             patch(module + 'is_middleware_disabled', return_value=False), patch(module + 'is_exempt', return_value=exempt), \
             patch(module + 'is_ip_exempted', return_value=False), patch(module + 'get_ip', return_value='93.184.216.90'), \
             patch(module + 'BlocklistManager.is_blocked', return_value=False), patch(module + 'get_keyword_store', return_value=store), \
             patch(module + 'path_exists_in_django', return_value=True), \
             patch.object(IPAndKeywordBlockMiddleware, '_collect_safe_prefixes', return_value=set()), \
             patch.object(IPAndKeywordBlockMiddleware, '_get_exempt_keywords', return_value=set()), \
             patch.object(IPAndKeywordBlockMiddleware, '_get_legitimate_path_keywords', return_value=set()):
            middleware = IPAndKeywordBlockMiddleware(handler)
            request = RequestFactory().generic('POST', '/login?' + query, wire_body(payload), content_type=content_type)
            result = middleware(request)
        return result.status_code, json.loads(result.content)
