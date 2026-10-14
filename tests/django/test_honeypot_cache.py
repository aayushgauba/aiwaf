"""Rust/Django honeypot cache timing, failure, and worker regressions."""
import json
import os
from pathlib import Path
import subprocess
import sys
from tempfile import TemporaryDirectory
import time
from types import SimpleNamespace
import warnings
from unittest.mock import patch

from django.core.cache import caches
from django.core.exceptions import ImproperlyConfigured
from django.test import SimpleTestCase, RequestFactory, override_settings
from aiwaf.django.csv_pipeline import NativeAIWAFMiddleware
from aiwaf.django.honeypot_cache import DjangoHoneypotCache
from tests.django.test_csv_pipeline import echo


class NativeHoneypotCacheTests(SimpleTestCase):
    def setUp(self):
        self.directory = TemporaryDirectory()
        self.addCleanup(self.directory.cleanup)
        self.now = time.time()
        self.config = {'data_dir': self.directory.name, 'enabled': ['honeypot'],
                       'exempt_paths': [], 'ip_blocking': False}
        self.settings = override_settings(ROOT_URLCONF='tests.django.test_csv_pipeline',
            AIWAF_CSV_PIPELINE=self.config,
            CACHES={'default': {'BACKEND': 'django.core.cache.backends.locmem.LocMemCache',
                                'LOCATION': self.directory.name}})
        self.settings.enable()
        self.addCleanup(self.settings.disable)

    def middleware(self):
        with warnings.catch_warnings():
            warnings.simplefilter('ignore', RuntimeWarning)
            return NativeAIWAFMiddleware(echo)

    def request(self, middleware, method='get', elapsed=0, path='/echo', authenticated=False):
        request = getattr(RequestFactory(), method)(path, REMOTE_ADDR='8.8.8.8')
        if authenticated:
            request.user = SimpleNamespace(is_authenticated=True)
        with patch('aiwaf.core.csv_pipeline.time.time', return_value=self.now + elapsed):
            return middleware(request)

    def test_django_defaults_to_cache_and_other_policies_stay_csv(self):
        first, second = self.middleware(), self.middleware()
        self.assertEqual(first.pipeline.profile['honeypot_backend'], 'django_cache')
        self.assertEqual(self.request(first).status_code, 200)
        self.assertEqual(self.request(second, 'post', .1).status_code, 403)
        self.assertEqual(self.request(second, 'post', 2).status_code, 200)
        self.assertFalse(Path(self.directory.name, 'pipeline_state.csv').exists())
        self.assertTrue(Path(self.directory.name, 'blacklist.csv').exists())

    def test_post_without_get_and_expired_ttl_allow(self):
        middleware = self.middleware()
        self.assertEqual(self.request(middleware, 'post').status_code, 200)
        self.request(middleware)
        self.assertEqual(self.request(middleware, 'post', 301).status_code, 200)

    def test_expired_page_requires_new_get_without_deleting_timestamp(self):
        middleware = self.middleware()
        self.request(middleware)
        self.assertEqual(self.request(middleware, 'post', 250).status_code, 409)
        self.assertEqual(self.request(middleware, 'post', 251).status_code, 409)
        self.request(middleware, elapsed=251)
        self.assertEqual(self.request(middleware, 'post', 253).status_code, 200)

    def test_stale_post_does_not_delete_concurrent_get(self):
        first, second = self.middleware(), self.middleware()
        self.request(first)
        backend = caches['default']
        original = backend.get
        def read_then_refresh(key, *args, **kwargs):
            snapshot = original(key, *args, **kwargs)
            # A newer worker finishes its GET after this POST read the old value.
            with patch.object(backend, 'get', original):
                self.assertEqual(self.request(second, elapsed=250).status_code, 200)
            return snapshot
        with patch.object(backend, 'get', side_effect=read_then_refresh):
            self.assertEqual(self.request(first, 'post', 250).status_code, 409)
        self.assertEqual(self.request(second, 'post', 252).status_code, 200)

    def test_get_writes_300_second_ttl_and_bounded_key(self):
        middleware = self.middleware()
        backend = caches['default']
        with patch.object(backend, 'set', wraps=backend.set) as setter:
            self.request(middleware)
        self.assertEqual(setter.call_args.kwargs['timeout'], 300)
        self.assertEqual(setter.call_args.args[1], (self.now, self.now + 300))
        self.assertLess(len(setter.call_args.args[0]), 200)

    def test_get_failure_and_false_write_return_503(self):
        middleware = self.middleware()
        for value in ('raise', False):
            with self.subTest(value=value), patch.object(caches['default'], 'set',
                    side_effect=ConnectionError('private-host-password') if value == 'raise' else None,
                    return_value=value):
                response = self.request(middleware)
                self.assertEqual(response.status_code, 503)
                self.assertNotIn(b'private-host-password', response.content)

    def test_post_cache_failure_is_503_instead_of_a_miss(self):
        middleware = self.middleware()
        with patch.object(caches['default'], 'get', side_effect=ConnectionError('private-host-password')):
            response = self.request(middleware, 'post')
        self.assertEqual(response.status_code, 503)
        self.assertNotIn(b'private-host-password', response.content)

    def test_malformed_cached_values_fail_closed(self):
        middleware = self.middleware()
        values = ['bad', (float('nan'), self.now + 300), (True, self.now + 300),
                  (self.now, self.now - 1), (self.now, float('inf'))]
        for value in values:
            with self.subTest(value=value), patch.object(caches['default'], 'get', return_value=value):
                self.assertEqual(self.request(middleware, 'post').status_code, 503)

    def test_json_serialized_timestamp_pairs_are_supported(self):
        middleware = self.middleware()
        with patch.object(caches['default'], 'get', return_value=[self.now, self.now + 300]):
            self.assertEqual(self.request(middleware, 'post', .1).status_code, 403)

    def test_async_cache_methods_are_rejected(self):
        middleware = self.middleware()
        async def asynchronous(*args, **kwargs):
            return None
        with patch.object(caches['default'], 'set', side_effect=asynchronous):
            self.assertEqual(self.request(middleware).status_code, 503)
        with patch.object(caches['default'], 'get', side_effect=asynchronous):
            self.assertEqual(self.request(middleware, 'post').status_code, 503)

    def test_exempt_and_authenticated_requests_do_not_call_cache(self):
        middleware = self.middleware()
        with patch.object(caches['default'], 'get', side_effect=AssertionError('unexpected cache read')), \
             patch.object(caches['default'], 'set', side_effect=AssertionError('unexpected cache write')):
            self.assertEqual(self.request(middleware, path='/exempt').status_code, 200)
            self.assertEqual(self.request(middleware, 'post', path='/exempt').status_code, 200)
            self.assertEqual(self.request(middleware, authenticated=True).status_code, 200)
            self.assertEqual(self.request(middleware, 'post', authenticated=True).status_code, 200)

    def test_dummy_cache_rejected_but_disabled_honeypot_needs_no_cache(self):
        with override_settings(CACHES={'default': {'BACKEND': 'django.core.cache.backends.dummy.DummyCache'}}):
            with self.assertRaises(ImproperlyConfigured):
                self.middleware()
            with override_settings(AIWAF_CSV_PIPELINE={**self.config, 'enabled': []}):
                self.assertEqual(self.request(self.middleware()).status_code, 200)

    def test_locmem_warning_and_invalid_alias(self):
        with self.assertWarnsRegex(RuntimeWarning, 'not shared across workers'):
            NativeAIWAFMiddleware(echo)
        for alias in ('', 12, 'not-configured'):
            with self.subTest(alias=alias), override_settings(AIWAF_CSV_PIPELINE={**self.config, 'honeypot_cache_alias': alias}):
                with self.assertRaises(ImproperlyConfigured):
                    self.middleware()

    def test_explicit_csv_and_memory_override_default(self):
        for backend in ('csv', 'memory'):
            with self.subTest(backend=backend), TemporaryDirectory() as directory, \
                 override_settings(AIWAF_CSV_PIPELINE={**self.config, 'data_dir': directory, 'honeypot_backend': backend}):
                self.assertEqual(self.middleware().pipeline.profile['honeypot_backend'], backend)

    def test_old_native_constructor_fails_with_upgrade_message(self):
        import aiwaf_rust
        def old_constructor(profile):
            raise AssertionError('old constructor should reject the second argument')
        with patch.object(aiwaf_rust, 'NativeCSVPipeline', old_constructor):
            with self.assertRaisesRegex(RuntimeError, 'aiwaf-rust>=0.2.6'):
                self.middleware()

    def test_fail_open_cache_configuration_rejected(self):
        for option in ('IGNORE_EXCEPTIONS', 'ignore_exc'):
            with self.subTest(option=option), override_settings(CACHES={'default': {
                'BACKEND': 'django.core.cache.backends.locmem.LocMemCache', 'OPTIONS': {option: True}}}):
                with self.assertRaises(ImproperlyConfigured):
                    self.middleware()

    def test_named_shared_cache_survives_independent_worker_process(self):
        with TemporaryDirectory() as shared, override_settings(CACHES={
            'default': {'BACKEND': 'django.core.cache.backends.dummy.DummyCache'},
            'honeypot': {'BACKEND': 'django.core.cache.backends.filebased.FileBasedCache', 'LOCATION': shared}},
            AIWAF_CSV_PIPELINE={**self.config, 'honeypot_cache_alias': 'honeypot'}):
            self.assertEqual(self.request(self.middleware()).status_code, 200)
            code = '''
import json, os, time
from django.conf import settings
settings.configure(SECRET_KEY='test', ROOT_URLCONF='tests.django.test_csv_pipeline',
    CACHES={'honeypot':{'BACKEND':'django.core.cache.backends.filebased.FileBasedCache',
                       'LOCATION':os.environ['AIWAF_TEST_CACHE_LOCATION']}},
    AIWAF_CSV_PIPELINE=json.loads(os.environ['AIWAF_TEST_PIPELINE']))
from aiwaf.django.csv_pipeline import NativeAIWAFMiddleware
from tests.django.test_csv_pipeline import echo
from django.test import RequestFactory
time.time=lambda: float(os.environ['AIWAF_TEST_NOW'])
response=NativeAIWAFMiddleware(echo)(RequestFactory().post('/echo', REMOTE_ADDR='8.8.8.8'))
assert response.status_code == 403, response.content
'''
            env = {**os.environ, 'AIWAF_TEST_CACHE_LOCATION': shared,
                   'AIWAF_TEST_PIPELINE': json.dumps({**self.config, 'honeypot_cache_alias': 'honeypot'}),
                   'AIWAF_TEST_NOW': str(self.now + .1)}
            result = subprocess.run([sys.executable, '-c', code], env=env, capture_output=True, text=True, timeout=45)
            self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
