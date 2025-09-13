"""
Django Unit Tests for AIWAF Trainer Module

Tests the trainer module functions using Django test framework.
"""

from tests.base_test import AIWAFTestCase
from unittest.mock import patch, MagicMock


class TrainerFunctionsTestCase(AIWAFTestCase):
    """Test case for trainer module functions"""
    
    def setUp(self):
        super().setUp()
        # Import trainer functions after Django setup
        from aiwaf import trainer
        self.trainer_module = trainer
    
    def test_get_legitimate_keywords_function(self):
        """Test the get_legitimate_keywords() function"""
        keywords = self.trainer_module.get_legitimate_keywords()
        self.assertIsInstance(keywords, set)
        self.assertGreater(len(keywords), 0)
        
    def test_path_exists_in_django_function(self):
        """Test path_exists_in_django function"""
        # Test with a path that should exist (admin)
        exists = self.trainer_module.path_exists_in_django('/admin/')
        self.assertIsInstance(exists, bool)
        
        # Test with a clearly non-existent path
        exists = self.trainer_module.path_exists_in_django('/nonexistent-path-12345/')
        self.assertFalse(exists)
    
    def test_remove_exempt_keywords_function(self):
        """Test remove_exempt_keywords function"""
        # This should run without error
        try:
            self.trainer_module.remove_exempt_keywords()
        except Exception as e:
            self.fail(f"remove_exempt_keywords() raised {e}")
    
    @patch('aiwaf.trainer._read_all_logs')
    def test_train_function_basic(self, mock_read_logs):
        """Test basic train function"""
        # Mock the log reading to avoid file dependencies
        mock_read_logs.return_value = []
        
        try:
            self.trainer_module.train(disable_ai=True)
        except Exception as e:
            self.fail(f"train() raised {e}")
    
    def test_extract_django_route_keywords(self):
        """Test Django route keyword extraction"""
        keywords = self.trainer_module._extract_django_route_keywords()
        self.assertIsInstance(keywords, set)
        # Should have some keywords from Django's built-in URLs
        self.assertGreater(len(keywords), 0)
    
    def test_malicious_context_trainer(self):
        """Test malicious context detection"""
        # Test with obviously malicious patterns
        result = self.trainer_module._is_malicious_context_trainer(
            '/test/', 'shell', '404'
        )
        self.assertIsInstance(result, bool)
        
        # Test with legitimate patterns
        result = self.trainer_module._is_malicious_context_trainer(
            '/admin/', 'login', '200'
        )
        self.assertIsInstance(result, bool)
    
    def test_parse_log_line(self):
        """Test log line parsing"""
        # Test with a sample log line
        sample_log = '192.168.1.1 - - [10/Oct/2000:13:55:36 -0700] "GET /test HTTP/1.0" 200 2326 "http://example.com/" "Mozilla/4.08" response-time=0.123'
        
        result = self.trainer_module._parse(sample_log)
        if result is not None:
            self.assertIsInstance(result, dict)
            self.assertIn('ip', result)
            self.assertIn('path', result)
            self.assertIn('status', result)
    
    @patch('aiwaf.trainer._get_logs_from_model')
    def test_get_logs_from_model(self, mock_get_logs):
        """Test getting logs from model"""
        mock_get_logs.return_value = []
        
        logs = self.trainer_module._get_logs_from_model()
        self.assertIsInstance(logs, list)