from tempfile import TemporaryDirectory
from unittest import skipUnless
from unittest.mock import patch
from django.http import JsonResponse
from django.test import SimpleTestCase, RequestFactory, override_settings
from django.urls import path
from aiwaf.django.decorators import aiwaf_exempt

try:
    import aiwaf_rust
except ImportError:
    aiwaf_rust = None


def echo(request):
    return JsonResponse({'body':request.body.decode(), 'ok':True})


urlpatterns = [path('echo', echo), path('exempt', aiwaf_exempt(echo))]


@skipUnless(aiwaf_rust and hasattr(aiwaf_rust, 'NativeCSVPipeline'), 'Native pipeline required')
class NativePipelineTests(SimpleTestCase):
    def test_native_django_policy_and_original_body(self):
        from aiwaf.django.csv_pipeline import NativeAIWAFMiddleware
        with TemporaryDirectory() as directory, override_settings(ROOT_URLCONF=__name__,
            AIWAF_CSV_PIPELINE={'data_dir':directory, 'rate_max':10000, 'rate_flood':20000,
                                'min_form_time':0, 'required_headers':[]}):
            middleware = NativeAIWAFMiddleware(echo)
            factory = RequestFactory()
            with patch('aiwaf.core.sql_injection.SQLInjectionPolicy.inspect', side_effect=AssertionError('Python SQL fallback')):
                response = middleware(factory.post('/echo', data='{"hello":"world"}', content_type='application/json'))
                assert response.status_code == 200
                assert b'hello' in response.content
                assert middleware(factory.get('/echo?q=union+select')).status_code == 403
                assert middleware(factory.get('/exempt?q=union+select')).status_code == 200
                assert middleware(factory.get('/wp-content/plugins/pods/init.php')).status_code == 403

    def test_native_django_bounded_body(self):
        from aiwaf.django.csv_pipeline import NativeAIWAFMiddleware
        with TemporaryDirectory() as directory, override_settings(ROOT_URLCONF=__name__,
            AIWAF_CSV_PIPELINE={'data_dir':directory, 'max_bytes':30, 'required_headers':[]}):
            middleware = NativeAIWAFMiddleware(echo)
            assert middleware(RequestFactory().post('/echo', data='x'*31, content_type='application/json')).status_code == 413
