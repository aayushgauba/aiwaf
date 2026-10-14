"""
Django Unit Tests for AIWAF Trainer Module

Tests the trainer module functions using Django test framework.
"""

from datetime import datetime
from unittest.mock import patch

from django.test import override_settings

from tests.django.base_test import AIWAFTestCase


class TrainerFunctionsTestCase(AIWAFTestCase):
    """Test case for trainer module functions"""
    
    def setUp(self):
        super().setUp()
        # Import trainer functions after Django setup
        from aiwaf.django import trainer
        self.trainer_module = trainer

    def test_model_log_wrapper_and_python_batch_flush(self):
        from aiwaf.django.models import RequestLog

        RequestLog.objects.create(
            ip_address="203.0.113.150",
            method="GET",
            path="/missing",
            status_code=404,
            response_time=0.1,
        )
        self.assertTrue(self.trainer_module._get_logs_from_model())
        line = '203.0.113.150 - - [30/Aug/2026:12:00:00 +0000] "GET /missing HTTP/1.1" 404 0 "-" "pytest" response-time=0.1\n'
        with patch.object(self.trainer_module, "MIN_TRAIN_LOGS", 1), patch.object(
            self.trainer_module, "_iter_all_logs", side_effect=lambda: iter([line])
        ), patch.object(self.trainer_module, "_should_use_rust_features", return_value=False), patch.object(
            self.trainer_module, "remove_exempt_keywords"
        ), patch.object(self.trainer_module, "get_legitimate_keywords", return_value=set()):
            self.trainer_module.train(disable_ai=True)
    
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
    
    @patch('aiwaf.django.trainer._read_all_logs')
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

    def test_parse_log_line_ipv6(self):
        """IPv6 client addresses are parsed and kept for training."""
        sample_log = '2001:db8::1 - - [10/Oct/2000:13:55:36 -0700] "GET /test-ipv6 HTTP/1.1" 200 2326 "-" "Mozilla/5.0" response-time=0.321'
        result = self.trainer_module._parse(sample_log)
        self.assertIsNotNone(result)
        self.assertEqual(result["ip"], "2001:db8::1")
        self.assertEqual(result["path"], "/test-ipv6")
        self.assertEqual(result["status"], "200")
    
    @patch('aiwaf.django.trainer._get_logs_from_model')
    def test_get_logs_from_model(self, mock_get_logs):
        """Test getting logs from model"""
        mock_get_logs.return_value = []
        
        logs = self.trainer_module._get_logs_from_model()
        self.assertIsInstance(logs, list)

    @override_settings(AIWAF_USE_RUST=True)
    def test_generate_feature_dicts_uses_rust_when_available(self):
        parsed = [{
            "ip": "1.1.1.1",
            "timestamp": datetime.now(),
            "path": "/test",
            "status": "200",
            "response_time": 0.2,
        }]
        ip_404 = {"1.1.1.1": 1}
        ip_times = {"1.1.1.1": [parsed[0]["timestamp"]]}

        with patch('aiwaf.django.trainer.path_exists_in_django', return_value=False), \
             patch('aiwaf.django.trainer.is_exempt_path', return_value=False), \
             patch('aiwaf.django.trainer.rust_available', return_value=True), \
             patch('aiwaf.django.trainer.rust_supports_chunked_features', return_value=False), \
             patch('aiwaf.django.trainer.core_extract_raw_features', return_value=None), \
             patch('aiwaf.django.trainer.rust_extract_features', return_value=[{"ip": "1.1.1.1"}]) as mock_rust:
            result = self.trainer_module._generate_feature_dicts(parsed, ip_404, ip_times)

        self.assertEqual(result, [{"ip": "1.1.1.1"}])
        mock_rust.assert_called_once()

    @override_settings(AIWAF_USE_RUST=True)
    def test_generate_feature_dicts_prefers_raw_rust_batch(self):
        parsed = [{
            "ip": "203.0.113.1", "path": "/probe", "status": "404",
            "timestamp": datetime(2025, 1, 1), "response_time": 0.1,
        }]
        expected = [{"ip": "203.0.113.1", "kw_hits": 1}]
        with patch("aiwaf.django.trainer._should_use_rust_features", return_value=True), \
             patch("aiwaf.django.trainer.core_extract_raw_features", return_value=expected) as raw, \
             patch("aiwaf.django.trainer.core_build_records", side_effect=AssertionError("old path used")):
            result = self.trainer_module._generate_feature_dicts(parsed, {"203.0.113.1": 1}, {})
        self.assertEqual(result, expected)
        raw.assert_called_once()

    @override_settings(
        AIWAF_USE_RUST=True,
        AIWAF_MIN_AI_LOGS=0,
        AIWAF_MIN_TRAIN_LOGS=1,
    )
    def test_train_uses_rust_isolation_forest_when_available(self):
        class StubRustIsolationForest:
            def __init__(self, **_kwargs):
                self.fitted = False

            def fit(self, _data):
                self.fitted = True

            def predict(self, data):
                return [1 for _ in data]

            def to_json(self):
                return {"stub": True}

        lines = ["line1", "line2"]
        rec = {
            "ip": "1.1.1.1",
            "timestamp": datetime.now(),
            "path": "/test",
            "status": "200",
            "response_time": 0.1,
        }

        with patch("aiwaf.django.trainer._iter_all_logs", side_effect=[lines, lines]), \
             patch("aiwaf.django.trainer._parse", return_value=rec), \
             patch("aiwaf.django.trainer.remove_exempt_keywords"), \
             patch("aiwaf.django.trainer.get_exemption_store") as mock_exempt_store, \
             patch("aiwaf.django.trainer.BlocklistManager.unblock"), \
             patch("aiwaf.django.trainer.BlocklistManager.block"), \
             patch("aiwaf.django.trainer.MIN_TRAIN_LOGS", 1), \
             patch("aiwaf.django.trainer.MIN_AI_LOGS", 0), \
             patch("aiwaf.django.trainer.PANDAS_AVAILABLE", True), \
             patch("aiwaf.django.trainer.SKLEARN_AVAILABLE", False), \
             patch("aiwaf.django.trainer.rust_isolation_forest_available", return_value=True), \
             patch("aiwaf.django.trainer.rust_isolation_forest_class", return_value=StubRustIsolationForest), \
             patch("aiwaf.django.trainer.save_model_data", return_value=True) as mock_save, \
             patch("aiwaf.django.trainer._python_feature_from_record", return_value={
                 "ip": "1.1.1.1",
                 "path_len": 4,
                 "kw_hits": 0,
                 "resp_time": 0.1,
                 "status_idx": 0,
                 "burst_count": 0,
                 "total_404": 0,
            }):
            mock_exempt_store.return_value.get_all.return_value = []
            self.trainer_module.train(disable_ai=False, force_ai=True)

        self.assertTrue(mock_save.called)
        saved_model_data = mock_save.call_args[0][0]
        self.assertEqual(saved_model_data.get("model_backend"), "aiwaf_rust")
        self.assertIn("model_state", saved_model_data)

    @override_settings(AIWAF_USE_RUST=True)
    def test_generate_feature_dicts_falls_back_when_rust_unavailable(self):
        ts = datetime(2025, 1, 1, 0, 0, 0)
        parsed = [{
            "ip": "2.2.2.2",
            "timestamp": ts,
            "path": "/.env",
            "status": "404",
            "response_time": 0.5,
        }]
        ip_404 = {"2.2.2.2": 3}
        ip_times = {"2.2.2.2": [ts]}

        with patch('aiwaf.django.trainer.path_exists_in_django', return_value=False), \
             patch('aiwaf.django.trainer.is_exempt_path', return_value=False), \
             patch('aiwaf.django.trainer.rust_available', return_value=False), \
             patch('aiwaf.django.trainer.rust_extract_features', return_value=None):
            result = self.trainer_module._generate_feature_dicts(parsed, ip_404, ip_times)

        expected = [{
            "ip": "2.2.2.2",
            "path_len": len('/.env'),
            "kw_hits": 1,
            "resp_time": 0.5,
            "status_idx": 2,
            "burst_count": 1,
            "total_404": 3,
        }]
        self.assertEqual(result, expected)

    def test_extract_rust_features_parallel_merges_in_order(self):
        records = [{"id": idx} for idx in range(5)]

        def fake_extract_features(chunk, _static_keywords):
            return [{"ip": str(item["id"])} for item in chunk]

        with patch("aiwaf.django.trainer.rust_extract_features", side_effect=fake_extract_features):
            result = self.trainer_module._extract_rust_features_parallel(
                records,
                [],
                chunk_size=2,
                max_workers=2,
            )

        self.assertEqual(result, [{"ip": "0"}, {"ip": "1"}, {"ip": "2"}, {"ip": "3"}, {"ip": "4"}])

    @override_settings(AIWAF_USE_RUST=True, AIWAF_RUST_FEATURE_CHUNK_SIZE=1)
    def test_generate_feature_dicts_uses_rust_batch_when_supported(self):
        parsed = [
            {
                "ip": "1.1.1.1",
                "timestamp": datetime(2025, 1, 1, 0, 0, 0),
                "path": "/test1",
                "status": "200",
                "response_time": 0.2,
            },
            {
                "ip": "2.2.2.2",
                "timestamp": datetime(2025, 1, 1, 0, 0, 1),
                "path": "/test2",
                "status": "200",
                "response_time": 0.3,
            },
        ]
        ip_404 = {"1.1.1.1": 0, "2.2.2.2": 0}
        ip_times = {
            "1.1.1.1": [parsed[0]["timestamp"]],
            "2.2.2.2": [parsed[1]["timestamp"]],
        }

        with patch("aiwaf.django.trainer.path_exists_in_django", return_value=False), \
             patch("aiwaf.django.trainer.is_exempt_path", return_value=False), \
             patch("aiwaf.django.trainer.rust_available", return_value=True), \
             patch("aiwaf.django.trainer.rust_supports_chunked_features", return_value=True), \
             patch("aiwaf.django.trainer.core_extract_raw_features", return_value=None), \
             patch("aiwaf.django.trainer.rust_extract_features_batch", side_effect=[([{"ip": "1.1.1.1"}], "s1"), ([{"ip": "2.2.2.2"}], "s2")]) as mock_batch, \
             patch("aiwaf.django.trainer.rust_finalize_feature_state", return_value=[]) as mock_finalize, \
             patch("aiwaf.django.trainer.rust_extract_features") as mock_single:
            result = self.trainer_module._generate_feature_dicts(parsed, ip_404, ip_times)

        self.assertEqual(result, [{"ip": "1.1.1.1"}, {"ip": "2.2.2.2"}])
        self.assertEqual(mock_batch.call_count, 2)
        mock_finalize.assert_called_once()
        mock_single.assert_not_called()

    @override_settings(
        AIWAF_USE_RUST=False,
        AIWAF_PYTHON_FEATURE_BATCH_SIZE=2,
        AIWAF_PYTHON_PARALLEL_FEATURES=True,
        AIWAF_PYTHON_PARALLEL_CHUNK_SIZE=2,
        AIWAF_PYTHON_PARALLEL_WORKERS=2,
    )
    def test_generate_feature_dicts_python_parallel_uses_threadpool(self):
        ts0 = datetime(2025, 1, 1, 0, 0, 0)
        ts1 = datetime(2025, 1, 1, 0, 0, 1)
        ts2 = datetime(2025, 1, 1, 0, 0, 2)
        ts3 = datetime(2025, 1, 1, 0, 0, 3)
        parsed = [
            {"ip": "9.9.9.9", "timestamp": ts0, "path": "/.env", "status": "404", "response_time": 0.1},
            {"ip": "9.9.9.9", "timestamp": ts1, "path": "/.env", "status": "404", "response_time": 0.1},
            {"ip": "9.9.9.9", "timestamp": ts2, "path": "/.env", "status": "404", "response_time": 0.1},
            {"ip": "9.9.9.9", "timestamp": ts3, "path": "/.env", "status": "404", "response_time": 0.1},
        ]
        ip_404 = {"9.9.9.9": 3}
        ip_times = {"9.9.9.9": [ts0, ts1, ts2, ts3]}

        class FakeExecutor:
            instances = []

            def __init__(self, max_workers=1):
                self.max_workers = max_workers
                self.map_calls = 0
                FakeExecutor.instances.append(self)

            def __enter__(self):
                return self

            def __exit__(self, exc_type, exc, tb):
                return False

            def map(self, fn, iterable):
                self.map_calls += 1
                return list(map(fn, iterable))

        with patch("aiwaf.django.trainer.rust_available", return_value=False), \
             patch("aiwaf.django.trainer.ThreadPoolExecutor", FakeExecutor), \
             patch("aiwaf.django.trainer.path_exists_in_django", return_value=False), \
             patch("aiwaf.django.trainer.is_exempt_path", return_value=False):
            result = self.trainer_module._generate_feature_dicts(parsed, ip_404, ip_times)

        expected = [{
            "ip": "9.9.9.9",
            "path_len": len("/.env"),
            "kw_hits": 1,
            "resp_time": 0.1,
            "status_idx": 2,
            "burst_count": 4,
            "total_404": 3,
        }] * 4
        self.assertEqual(result, expected)
        self.assertGreater(len(FakeExecutor.instances), 0)
        self.assertGreater(sum(ex.map_calls for ex in FakeExecutor.instances), 0)
