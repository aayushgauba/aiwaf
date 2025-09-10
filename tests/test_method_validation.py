#!/usr/bin/env python3
"""
Test comprehensive HTTP method validation in HoneypotTimingMiddleware

This test verifies that the middleware correctly:
1. Blocks GET requests to POST-only views
2. Blocks POST requests to GET-only views  
3. Blocks other methods (PUT, DELETE) to views that don't support them
4. Allows valid method combinations
"""

import os
import sys
import django
from django.test import TestCase, RequestFactory
from django.http import JsonResponse
from django.views import View
from django.views.generic import CreateView, ListView, DetailView
from django.urls import path, reverse
from unittest.mock import patch, MagicMock

# Add the current directory to Python path for imports
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

# Configure Django settings
os.environ.setdefault('DJANGO_SETTINGS_MODULE', 'django.conf.global_settings')

import django
from django.conf import settings

if not settings.configured:
    settings.configure(
        DEBUG=True,
        SECRET_KEY='test-secret-key-for-testing-only',
        USE_TZ=True,
        ROOT_URLCONF=__name__,  # Use this module as URL config
        MIDDLEWARE=[
            'aiwaf.middleware.HoneypotTimingMiddleware',
        ],
        INSTALLED_APPS=[
            'django.contrib.contenttypes',
            'django.contrib.auth',
            'aiwaf',
        ],
        DATABASES={
            'default': {
                'ENGINE': 'django.db.backends.sqlite3',
                'NAME': ':memory:',
            }
        },
        CACHES={
            'default': {
                'BACKEND': 'django.core.cache.backends.locmem.LocMemCache',
            }
        },
    )

django.setup()

# Test views for different method scenarios
class PostOnlyView(View):
    """View that only accepts POST requests"""
    http_method_names = ['post']
    
    def post(self, request):
        return JsonResponse({'status': 'success'})

class GetOnlyView(View):
    """View that only accepts GET requests"""
    http_method_names = ['get']
    
    def get(self, request):
        return JsonResponse({'status': 'success'})

class GetPostView(View):
    """View that accepts both GET and POST"""
    http_method_names = ['get', 'post']
    
    def get(self, request):
        return JsonResponse({'method': 'get'})
        
    def post(self, request):
        return JsonResponse({'method': 'post'})

class RestApiView(View):
    """View that accepts REST methods"""
    http_method_names = ['get', 'post', 'put', 'delete']
    
    def get(self, request):
        return JsonResponse({'method': 'get'})
        
    def post(self, request):
        return JsonResponse({'method': 'post'})
        
    def put(self, request):
        return JsonResponse({'method': 'put'})
        
    def delete(self, request):
        return JsonResponse({'method': 'delete'})

def function_get_only(request):
    """Function-based view that only handles GET"""
    if request.method == 'GET':
        return JsonResponse({'status': 'success'})
    return JsonResponse({'error': 'Method not allowed'}, status=405)

def function_post_only(request):
    """Function-based view that only handles POST"""
    if request.method == 'POST':
        return JsonResponse({'status': 'success'})
    return JsonResponse({'error': 'Method not allowed'}, status=405)

# URL patterns for testing
urlpatterns = [
    path('post-only/', PostOnlyView.as_view(), name='post_only'),
    path('get-only/', GetOnlyView.as_view(), name='get_only'),
    path('get-post/', GetPostView.as_view(), name='get_post'),
    path('rest-api/', RestApiView.as_view(), name='rest_api'),
    path('func-get/', function_get_only, name='func_get'),
    path('func-post/', function_post_only, name='func_post'),
]

class MethodValidationTest(TestCase):
    def setUp(self):
        self.factory = RequestFactory()
        
        # Mock exemption store and blacklist manager
        self.exemption_patcher = patch('aiwaf.middleware.get_exemption_store')
        self.blacklist_patcher = patch('aiwaf.middleware.BlacklistManager')
        
        self.mock_exemption_store = self.exemption_patcher.start()
        self.mock_blacklist = self.blacklist_patcher.start()
        
        # Configure mocks
        mock_store_instance = MagicMock()
        mock_store_instance.is_exempted.return_value = False
        self.mock_exemption_store.return_value = mock_store_instance
        
        self.mock_blacklist.is_blocked.return_value = True
        self.mock_blacklist.block.return_value = None
        
        # Import and initialize middleware
        from aiwaf.middleware import HoneypotTimingMiddleware
        self.middleware = HoneypotTimingMiddleware(get_response=lambda request: None)
    
    def tearDown(self):
        self.exemption_patcher.stop()
        self.blacklist_patcher.stop()
    
    def test_get_to_post_only_view_blocked(self):
        """Test that GET requests to POST-only views are blocked"""
        request = self.factory.get('/post-only/')
        request.path = '/post-only/'
        
        response = self.middleware.process_request(request)
        
        # Should be blocked
        self.assertIsInstance(response, JsonResponse)
        self.assertEqual(response.status_code, 405)
        self.mock_blacklist.block.assert_called()
        
        # Check block reason
        block_call = self.mock_blacklist.block.call_args
        self.assertIn("GET to POST-only view", block_call[0][1])
    
    def test_post_to_get_only_view_blocked(self):
        """Test that POST requests to GET-only views are blocked"""
        request = self.factory.post('/get-only/')
        request.path = '/get-only/'
        
        response = self.middleware.process_request(request)
        
        # Should be blocked
        self.assertIsInstance(response, JsonResponse)
        self.assertEqual(response.status_code, 405)
        self.mock_blacklist.block.assert_called()
        
        # Check block reason
        block_call = self.mock_blacklist.block.call_args
        self.assertIn("POST to GET-only view", block_call[0][1])
    
    def test_valid_get_to_get_view_allowed(self):
        """Test that GET requests to GET-accepting views are allowed"""
        request = self.factory.get('/get-only/')
        request.path = '/get-only/'
        
        response = self.middleware.process_request(request)
        
        # Should not be blocked - just return None to continue processing
        self.assertIsNone(response)
        self.mock_blacklist.block.assert_not_called()
    
    def test_valid_post_to_post_view_allowed(self):
        """Test that POST requests to POST-accepting views check timing"""
        # First make a GET request to set up timing
        get_request = self.factory.get('/get-post/')
        get_request.path = '/get-post/'
        self.middleware.process_request(get_request)
        
        # Then make POST request
        post_request = self.factory.post('/get-post/')
        post_request.path = '/get-post/'
        
        # Should not be blocked for method mismatch
        response = self.middleware.process_request(post_request)
        
        # Might be blocked for timing, but not for method mismatch
        if response and isinstance(response, JsonResponse):
            # If blocked, it should be for timing, not method
            self.assertNotEqual(response.status_code, 405)
    
    def test_put_to_non_rest_view_blocked(self):
        """Test that PUT requests to views that don't support PUT are blocked"""
        request = self.factory.put('/get-only/')
        request.path = '/get-only/'
        
        response = self.middleware.process_request(request)
        
        # Should be blocked
        self.assertIsInstance(response, JsonResponse)
        self.assertEqual(response.status_code, 405)
        self.mock_blacklist.block.assert_called()
        
        # Check block reason
        block_call = self.mock_blacklist.block.call_args
        self.assertIn("PUT to view that doesn't support it", block_call[0][1])
    
    def test_delete_to_rest_view_allowed(self):
        """Test that DELETE requests to REST views are allowed"""
        request = self.factory.delete('/rest-api/')
        request.path = '/rest-api/'
        
        response = self.middleware.process_request(request)
        
        # Should not be blocked for method mismatch
        if response:
            self.assertNotEqual(response.status_code, 405)
        else:
            # None means allowed to continue
            self.assertIsNone(response)
    
    def test_function_based_view_get_validation(self):
        """Test method validation on function-based views"""
        # POST to GET-only function view
        request = self.factory.post('/func-get/')
        request.path = '/func-get/'
        
        response = self.middleware.process_request(request)
        
        # Should be blocked
        self.assertIsInstance(response, JsonResponse)
        self.assertEqual(response.status_code, 405)
    
    def test_function_based_view_post_validation(self):
        """Test POST validation on function-based views"""
        # GET to POST-only function view
        request = self.factory.get('/func-post/')
        request.path = '/func-post/'
        
        response = self.middleware.process_request(request)
        
        # Should be blocked
        self.assertIsInstance(response, JsonResponse)
        self.assertEqual(response.status_code, 405)
    
    def test_head_options_always_allowed(self):
        """Test that HEAD and OPTIONS requests are typically allowed"""
        for method in ['HEAD', 'OPTIONS']:
            request = getattr(self.factory, method.lower())('/get-only/')
            request.path = '/get-only/'
            request.method = method
            
            response = self.middleware.process_request(request)
            
            # Should not be blocked for method validation
            if response:
                self.assertNotEqual(response.status_code, 405)

def run_tests():
    """Run the method validation tests"""
    print("Testing HTTP Method Validation in HoneypotTimingMiddleware...")
    print("=" * 70)
    
    # Create test suite
    from django.test.utils import get_runner
    from django.conf import settings
    
    TestRunner = get_runner(settings)
    test_runner = TestRunner(verbosity=2, interactive=False, keepdb=False)
    
    # Run tests
    failures = test_runner.run_tests(['__main__'])
    
    if failures:
        print(f"\n❌ {failures} test(s) failed!")
        return False
    else:
        print("\n✅ All method validation tests passed!")
        return True

if __name__ == '__main__':
    success = run_tests()
    sys.exit(0 if success else 1)
