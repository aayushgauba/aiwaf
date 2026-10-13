"""Django-native tests for CSV geo fusion and retained ORM country blocks."""
from contextlib import ExitStack
from tempfile import TemporaryDirectory
from unittest import skipUnless
from unittest.mock import patch
from django.test import TestCase, RequestFactory, override_settings
from django.core.exceptions import PermissionDenied
from aiwaf.core import rust_backend

try:
    import aiwaf_rust
except ImportError:
    aiwaf_rust = None


@skipUnless(aiwaf_rust and hasattr(aiwaf_rust, 'csv_geo_policy'), 'Requires rebuilt geo extension')
class CombinedCSVGeoTests(TestCase):
    def setUp(self):
        directory = TemporaryDirectory()
        self.addCleanup(directory.cleanup)
        stack = ExitStack()
        self.addCleanup(stack.close)
        stack.enter_context(override_settings(AIWAF_STORAGE_MODE='csv', AIWAF_DATA_DIR=directory.name,
            AIWAF_USE_RUST=True, AIWAF_RUST_CSV=True, AIWAF_GEO_BLOCK_ENABLED=True,
            AIWAF_GEO_BLOCK_COUNTRIES=['CN'], AIWAF_GEO_ALLOW_COUNTRIES=[], AIWAF_EXEMPT_IPS=[]))
        stack.enter_context(patch.object(rust_backend, 'aiwaf_rust', aiwaf_rust))
        from aiwaf.django import middleware as mw, storage
        self.mw = mw
        stack.enter_context(patch.object(mw, 'is_exempt', return_value=False))
        stack.enter_context(patch.object(mw, 'is_ip_exempted', return_value=False))
        stack.enter_context(patch.object(mw, 'is_middleware_disabled', return_value=False))
        stack.enter_context(patch.object(mw, 'lookup_country', return_value='US'))
        storage._ensure_runtime_csv_backend()
        self.request = RequestFactory().get('/private', REMOTE_ADDR='203.0.113.90')

    def test_csv_changes_visible_and_allowlist_precedence(self):
        from aiwaf.core.runtime_storage import get_geo_block_store
        middleware = self.mw.GeoBlockMiddleware(lambda _: None)
        self.assertIsNone(middleware.process_request(self.request))
        get_geo_block_store().add_country('US')
        with self.assertRaises(PermissionDenied):
            middleware.process_request(self.request)
        get_geo_block_store().remove_country('US')
        self.assertIsNone(middleware.process_request(self.request))
        get_geo_block_store().add_country('US')
        with override_settings(AIWAF_GEO_ALLOW_COUNTRIES=['US']):
            self.assertIsNone(self.mw.GeoBlockMiddleware(lambda _: None).process_request(self.request))

    def test_existing_orm_blocks_are_retained(self):
        from aiwaf.django.models import GeoBlockedCountry
        GeoBlockedCountry.objects.create(country_code='US')
        with self.assertRaises(PermissionDenied):
            self.mw.GeoBlockMiddleware(lambda _: None).process_request(self.request)

    def test_exemption_and_disabled_native(self):
        from aiwaf.core.runtime_storage import get_geo_block_store
        get_geo_block_store().add_country('US')
        with patch.object(aiwaf_rust, 'csv_geo_policy', side_effect=AssertionError('Unexpected native geo')):
            with patch.object(self.mw, 'is_exempt', return_value=True):
                self.assertIsNone(self.mw.GeoBlockMiddleware(lambda _: None).process_request(self.request))
            with override_settings(AIWAF_USE_RUST=False):
                with self.assertRaises(PermissionDenied):
                    self.mw.GeoBlockMiddleware(lambda _: None).process_request(self.request)
