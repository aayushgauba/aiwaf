from contextlib import ExitStack
from tempfile import TemporaryDirectory
from unittest import skipUnless
from django.test import TestCase, RequestFactory, override_settings
from django.http import JsonResponse
from django.urls import path

try:
    import aiwaf_rust
except ImportError:
    aiwaf_rust = None

urlpatterns = [path('safe', lambda request: JsonResponse({'ok': True}))]


@skipUnless(aiwaf_rust and hasattr(aiwaf_rust, 'NativeRequestEngine'), 'Requires compiled request engine')
class RequestEngineTests(TestCase):
    def test_django_keeps_sql_before_route_callbacks_and_uses_csv_stage(self):
        from aiwaf.django.middleware import IPAndKeywordBlockMiddleware
        from aiwaf.django import storage
        from unittest.mock import patch
        with TemporaryDirectory() as directory, override_settings(ROOT_URLCONF=__name__,
            AIWAF_STORAGE_MODE='csv', AIWAF_DATA_DIR=directory, AIWAF_RUST_REQUEST_ENGINE=True,
            AIWAF_USE_RUST=True, AIWAF_RUST_CSV=True, AIWAF_EXEMPT_PATHS=[], AIWAF_EXEMPT_IPS=[]):
            storage._ensure_runtime_csv_backend()
            middleware = IPAndKeywordBlockMiddleware(lambda request: JsonResponse({'ok': True}))
            factory = RequestFactory()
            assert middleware(factory.get('/safe', REMOTE_ADDR='203.0.113.97')).status_code == 200
            assert hasattr(middleware, '_native_request_engine_profile')
            with patch('aiwaf.django.middleware.path_exists_in_django', side_effect=AssertionError('SQL must run first')):
                assert middleware(factory.get('/safe?q=1+UNION+SELECT', REMOTE_ADDR='203.0.113.97')).status_code == 403
