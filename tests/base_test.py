"""
Base Test Classes for AIWAF Django Unit Tests
"""

import os
import sys
import django
from django.test import TestCase, RequestFactory, TransactionTestCase
from django.conf import settings
from django.core.management import execute_from_command_line
from unittest.mock import patch, MagicMock

# Setup Django if not already configured
if not settings.configured:
    os.environ.setdefault('DJANGO_SETTINGS_MODULE', 'tests.test_settings')
    django.setup()

class AIWAFTestCase(TestCase):
    """Base test case for AIWAF tests"""
    
    def setUp(self):
        """Set up test fixtures"""
        self.factory = RequestFactory()
        self.setup_aiwaf_test_environment()
    
    def setup_aiwaf_test_environment(self):
        """Setup AIWAF-specific test environment"""
        # Clear any existing AIWAF caches/state
        from django.core.cache import cache
        cache.clear()
        
        # Reset any global AIWAF state
        try:
            from aiwaf.storage import Storage
            Storage._instance = None
        except ImportError:
            pass
    
    def create_request(self, path='/', method='GET', headers=None, data=None):
        """Helper to create test requests with proper headers"""
        if headers is None:
            headers = {
                'HTTP_USER_AGENT': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36',
                'HTTP_ACCEPT': 'text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8',
                'HTTP_ACCEPT_LANGUAGE': 'en-US,en;q=0.5',
                'HTTP_ACCEPT_ENCODING': 'gzip, deflate',
                'HTTP_CONNECTION': 'keep-alive',
            }
        
        if method.upper() == 'GET':
            request = self.factory.get(path, **headers)
        elif method.upper() == 'POST':
            request = self.factory.post(path, data or {}, **headers)
        else:
            request = getattr(self.factory, method.lower())(path, data or {}, **headers)
        
        # Add session and user attributes
        request.session = {}
        request.user = None
        
        return request
    
    def create_bot_request(self, path='/', bot_type='scanner'):
        """Helper to create bot-like requests"""
        bot_headers = {
            'scanner': {
                'HTTP_USER_AGENT': 'sqlmap/1.0',
                'HTTP_CONNECTION': 'close',
            },
            'legitimate_bot': {
                'HTTP_USER_AGENT': 'Googlebot/2.1 (+http://www.google.com/bot.html)',
                'HTTP_ACCEPT': '*/*',
            },
            'suspicious': {
                'HTTP_USER_AGENT': 'python-requests/2.25.1',
                'HTTP_CONNECTION': 'close',
            }
        }
        return self.create_request(path, headers=bot_headers.get(bot_type, {}))


class AIWAFMiddlewareTestCase(AIWAFTestCase):
    """Base test case for middleware tests"""
    
    def setUp(self):
        super().setUp()
        self.setup_middleware_mocks()
    
    def setup_middleware_mocks(self):
        """Setup common middleware mocks"""
        # Mock the get_response callable
        self.mock_get_response = MagicMock()
        self.mock_get_response.return_value = MagicMock()
        self.mock_get_response.return_value.status_code = 200
    
    def process_request_through_middleware(self, middleware_class, request):
        """Helper to process a request through middleware"""
        middleware = middleware_class(self.mock_get_response)
        
        # Process request
        response = middleware.process_request(request)
        if response:
            return response
        
        # Call the view (mocked)
        response = middleware(request)
        return response


class AIWAFStorageTestCase(TransactionTestCase):
    """Base test case for storage/database tests that need transactions"""
    
    def setUp(self):
        """Set up storage test fixtures"""
        self.factory = RequestFactory()
        self.setup_storage_test_environment()
    
    def setup_storage_test_environment(self):
        """Setup storage-specific test environment"""
        from django.core.cache import cache
        cache.clear()
        
        # Ensure fresh database state
        from django.core.management import call_command
        call_command('migrate', verbosity=0, interactive=False)


class AIWAFTrainerTestCase(AIWAFTestCase):
    """Base test case for trainer tests"""
    
    def setUp(self):
        super().setUp()
        self.setup_trainer_test_environment()
    
    def setup_trainer_test_environment(self):
        """Setup trainer-specific test environment"""
        # Mock Django URL patterns for testing
        self.mock_url_patterns = [
            {'pattern': 'admin/', 'name': 'admin'},
            {'pattern': 'api/users/', 'name': 'api_users'},
            {'pattern': 'login/', 'name': 'login'},
            {'pattern': 'profile/', 'name': 'profile'},
        ]
    
    def get_mock_url_patterns(self):
        """Return mock URL patterns for testing"""
        return self.mock_url_patterns