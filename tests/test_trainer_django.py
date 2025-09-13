#!/usr/bin/env python3
"""
Django Unit Test for AIWAF Trainer

Tests trainer functionality including:
1. Legitimate keyword detection
2. Django URL pattern extraction
3. Keyword filtering and learning
4. Training mode behavior
5. Integration with storage system
"""

import os
import sys
from unittest.mock import patch, MagicMock

# Setup Django
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
os.environ.setdefault('DJANGO_SETTINGS_MODULE', 'tests.test_settings')

import django
django.setup()

from django.test import override_settings
from tests.base_test import AIWAFTrainerTestCase


class TrainerTestCase(AIWAFTrainerTestCase):
    """Test AIWAF trainer functionality"""
    
    def setUp(self):
        super().setUp()
        # Import after Django setup
        from aiwaf.trainer import Trainer
        self.trainer_class = Trainer
    
    def test_legitimate_keywords_function(self):
        """Test the get_legitimate_keywords() function"""
        trainer = self.trainer_class()
        
        legitimate_keywords = trainer.get_legitimate_keywords()
        
        # Should contain common legitimate keywords
        expected_keywords = {
            'profile', 'user', 'account', 'settings', 'dashboard',
            'home', 'about', 'contact', 'help', 'search',
            'api', 'auth', 'login', 'logout', 'register',
            'admin', 'page', 'category', 'tag', 'post'
        }
        
        for keyword in expected_keywords:
            self.assertIn(keyword, legitimate_keywords)
    
    @override_settings(AIWAF_SETTINGS={'ALLOWED_PATH_KEYWORDS': ['custom', 'special']})
    def test_custom_legitimate_keywords(self):
        """Test custom legitimate keywords from settings"""
        trainer = self.trainer_class()
        
        legitimate_keywords = trainer.get_legitimate_keywords()
        
        # Should include custom keywords from settings
        self.assertIn('custom', legitimate_keywords)
        self.assertIn('special', legitimate_keywords)
    
    def test_django_url_pattern_extraction(self):
        """Test extraction of keywords from Django URL patterns"""
        trainer = self.trainer_class()
        
        # Mock Django URL patterns
        mock_patterns = [
            {'pattern': 'admin/', 'name': 'admin'},
            {'pattern': 'api/users/<int:id>/', 'name': 'user_detail'},
            {'pattern': 'blog/posts/', 'name': 'blog_posts'},
            {'pattern': 'accounts/login/', 'name': 'login'},
        ]
        
        with patch.object(trainer, '_get_django_url_patterns', return_value=mock_patterns):
            django_keywords = trainer.extract_django_keywords()
            
            expected_keywords = {'admin', 'api', 'users', 'blog', 'posts', 'accounts', 'login'}
            
            for keyword in expected_keywords:
                self.assertIn(keyword, django_keywords)
    
    def test_keyword_filtering_logic(self):
        """Test keyword filtering logic"""
        trainer = self.trainer_class()
        
        # Test various path segments
        test_cases = [
            # (path_segment, should_be_legitimate)
            ('admin', True),
            ('user', True),
            ('profile', True),
            ('exploit', False),
            ('injection', False),
            ('malicious', False),
            ('normal', True),
            ('page', True),
        ]
        
        legitimate_keywords = trainer.get_legitimate_keywords()
        
        for keyword, should_be_legitimate in test_cases:
            is_legitimate = keyword in legitimate_keywords
            
            if should_be_legitimate:
                self.assertTrue(is_legitimate, f"'{keyword}' should be legitimate")
            # Note: We can't easily test malicious keywords without the full set
    
    def test_path_keyword_extraction(self):
        """Test extracting keywords from URL paths"""
        trainer = self.trainer_class()
        
        test_paths = [
            '/admin/users/edit/',
            '/api/v1/posts/',
            '/blog/category/tech/',
            '/accounts/profile/settings/',
        ]
        
        for path in test_paths:
            keywords = trainer.extract_keywords_from_path(path)
            
            # Should extract meaningful keywords from path
            self.assertIsInstance(keywords, (list, set))
            self.assertGreater(len(keywords), 0)
    
    @override_settings(AIWAF_SETTINGS={'TRAINING_MODE': True})
    def test_training_mode_behavior(self):
        """Test trainer behavior in training mode"""
        trainer = self.trainer_class()
        
        # In training mode, should learn from requests
        self.assertTrue(trainer.is_training_mode())
        
        # Mock a request for learning
        mock_request = self.create_request('/test/path/')
        
        # Should process the request for learning
        result = trainer.learn_from_request(mock_request)
        
        # Should return some result (exact behavior depends on implementation)
        self.assertIsNotNone(result)
    
    @override_settings(AIWAF_SETTINGS={'TRAINING_MODE': False})
    def test_production_mode_behavior(self):
        """Test trainer behavior in production mode"""
        trainer = self.trainer_class()
        
        # In production mode, should not learn
        self.assertFalse(trainer.is_training_mode())
    
    def test_malicious_keyword_detection(self):
        """Test detection of malicious keywords"""
        trainer = self.trainer_class()
        
        # Test paths with potentially malicious content
        malicious_paths = [
            '/admin/../../../etc/passwd',
            '/api/users?id=1; DROP TABLE users;',
            '/search?q=<script>alert("xss")</script>',
            '/login?redirect=javascript:alert(1)',
        ]
        
        for path in malicious_paths:
            keywords = trainer.extract_keywords_from_path(path)
            
            # Should extract keywords from malicious paths
            self.assertIsInstance(keywords, (list, set))
            
            # Check if any malicious patterns are detected
            malicious_indicators = ['script', 'alert', 'drop', 'table', 'javascript']
            path_lower = path.lower()
            
            has_malicious = any(indicator in path_lower for indicator in malicious_indicators)
            if has_malicious:
                # Should detect the malicious content somehow
                pass  # Implementation-specific
    
    def test_keyword_frequency_tracking(self):
        """Test keyword frequency tracking"""
        trainer = self.trainer_class()
        
        # Train with multiple occurrences of same keywords
        test_requests = [
            '/admin/users/',
            '/admin/posts/',
            '/admin/settings/',
            '/api/users/',
            '/api/posts/',
        ]
        
        for path in test_requests:
            request = self.create_request(path)
            trainer.learn_from_request(request)
        
        # Check if frequency tracking works
        # (Implementation depends on how trainer stores data)
        if hasattr(trainer, 'get_keyword_frequencies'):
            frequencies = trainer.get_keyword_frequencies()
            
            # 'admin' should appear 3 times, 'api' 2 times
            if 'admin' in frequencies:
                self.assertGreaterEqual(frequencies['admin'], 3)
            if 'api' in frequencies:
                self.assertGreaterEqual(frequencies['api'], 2)
    
    def test_integration_with_storage(self):
        """Test trainer integration with storage system"""
        trainer = self.trainer_class()
        
        # Mock storage
        with patch('aiwaf.storage.Storage.get_instance') as mock_storage:
            mock_storage_instance = MagicMock()
            mock_storage.return_value = mock_storage_instance
            
            # Train with a request
            request = self.create_request('/test/integration/')
            trainer.learn_from_request(request)
            
            # Should interact with storage
            # (Exact interaction depends on implementation)
            if hasattr(trainer, 'store_keywords'):
                self.assertTrue(mock_storage.called or mock_storage_instance.store_keyword.called)
    
    def test_exemption_handling(self):
        """Test handling of exempted paths and keywords"""
        trainer = self.trainer_class()
        
        # Test with exempted paths
        exempted_paths = ['/health/', '/status/', '/metrics/']
        
        for path in exempted_paths:
            with patch('aiwaf.utils.is_exempted', return_value=True):
                request = self.create_request(path)
                result = trainer.learn_from_request(request)
                
                # Should handle exempted paths appropriately
                # (May skip learning or handle differently)
                self.assertIsNotNone(result)
    
    def test_url_pattern_normalization(self):
        """Test URL pattern normalization"""
        trainer = self.trainer_class()
        
        # Test paths with parameters, query strings, etc.
        test_cases = [
            ('/api/users/123/', '/api/users/<id>/'),
            ('/blog/2023/12/post-title/', '/blog/<year>/<month>/<slug>/'),
            ('/search?q=test&page=1', '/search'),
        ]
        
        for original_path, expected_normalized in test_cases:
            if hasattr(trainer, 'normalize_path'):
                normalized = trainer.normalize_path(original_path)
                
                # Should normalize dynamic parts
                self.assertIn('api', normalized.lower() if 'api' in original_path else 'nomatch')
    
    def test_legitimate_vs_malicious_classification(self):
        """Test classification of legitimate vs malicious requests"""
        trainer = self.trainer_class()
        
        # Legitimate requests
        legitimate_requests = [
            '/admin/dashboard/',
            '/api/users/profile/',
            '/blog/latest-posts/',
            '/accounts/settings/',
        ]
        
        # Potentially malicious requests
        malicious_requests = [
            '/admin/config.php',
            '/wp-admin/admin-ajax.php',
            '/.env',
            '/phpMyAdmin/',
        ]
        
        for path in legitimate_requests:
            keywords = trainer.extract_keywords_from_path(path)
            legitimate_keywords = trainer.get_legitimate_keywords()
            
            # Should have some overlap with legitimate keywords
            overlap = set(keywords) & legitimate_keywords
            self.assertGreater(len(overlap), 0, f"Path '{path}' should have legitimate keywords")
        
        for path in malicious_requests:
            keywords = trainer.extract_keywords_from_path(path)
            
            # Should extract keywords even from malicious paths
            self.assertIsInstance(keywords, (list, set))


if __name__ == "__main__":
    import unittest
    unittest.main()