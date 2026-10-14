"""Comprehensive concurrent access tests for CSV storage improvements."""

import pytest
import threading
import time
import random
import tempfile
import concurrent.futures
from pathlib import Path
from aiwaf.core.storage_schema import BLOCKLIST_CSV, CSV_HEADERS
from aiwaf.flask.storage import (
    add_ip_allowlist, is_ip_allowlisted, add_ip_blocklist,
    is_ip_blocklisted, add_keyword, _get_data_dir
)


@pytest.fixture
def concurrent_csv_app(app):
    """App fixture configured for concurrent CSV testing."""
    with app.app_context():
        temp_dir = tempfile.mkdtemp()
        app.config['AIWAF_USE_CSV'] = True
        app.config['AIWAF_DATA_DIR'] = temp_dir
        app.config['AIWAF_RATE_WINDOW'] = 60
        app.config['AIWAF_RATE_MAX'] = 100
        yield app


class TestConcurrentCSVAccess:
    """Test suite for concurrent CSV access improvements."""

    def test_concurrent_allowlist_operations(self, concurrent_csv_app):
        """Test concurrent allowlist add/check operations."""
        num_threads = 20
        num_operations = 50
        results = {'success': 0, 'errors': []}
        
        def worker(thread_id):
            """Worker function for concurrent operations."""
            with concurrent_csv_app.app_context():
                try:
                    for i in range(num_operations):
                        ip = f"192.168.{thread_id}.{i}"
                        
                        # Add IP to allowlist
                        add_ip_allowlist(ip)
                        
                        # Small random delay to increase contention
                        time.sleep(random.uniform(0.001, 0.005))
                        
                        # Verify IP was added
                        if is_ip_allowlisted(ip):
                            results['success'] += 1
                        else:
                            results['errors'].append(f"Thread {thread_id}: IP {ip} not found after adding")
                            
                except Exception as e:
                    results['errors'].append(f"Thread {thread_id}: {str(e)}")
        
        # Run concurrent operations
        threads = []
        for i in range(num_threads):
            thread = threading.Thread(target=worker, args=(i,))
            threads.append(thread)
            thread.start()
        
        # Wait for all threads to complete
        for thread in threads:
            thread.join()
        
        # Verify results
        expected_operations = num_threads * num_operations
        assert results['success'] == expected_operations, f"Expected {expected_operations} success, got {results['success']}. Errors: {results['errors']}"
        assert len(results['errors']) == 0, f"Unexpected errors: {results['errors']}"

    def test_concurrent_blocklist_operations(self, concurrent_csv_app):
        """Test concurrent blocklist add/check operations."""
        num_threads = 15
        num_operations = 30
        results = {'success': 0, 'errors': []}
        
        def worker(thread_id):
            """Worker function for concurrent blocklist operations."""
            try:
                for i in range(num_operations):
                    ip = f"10.0.{thread_id}.{i}"
                    reason = f"Malicious activity from thread {thread_id}"
                    
                    # Add IP to blocklist
                    add_ip_blocklist(ip, reason)
                    
                    # Small random delay
                    time.sleep(random.uniform(0.001, 0.003))
                    
                    # Verify IP was blocklisted
                    if is_ip_blocklisted(ip):
                        results['success'] += 1
                    else:
                        results['errors'].append(f"Thread {thread_id}: IP {ip} not blocklisted after adding")
                        
            except Exception as e:
                results['errors'].append(f"Thread {thread_id}: {str(e)}")
        
        # Run concurrent operations
        threads = []
        for i in range(num_threads):
            thread = threading.Thread(target=worker, args=(i,))
            threads.append(thread)
            thread.start()
        
        # Wait for completion
        for thread in threads:
            thread.join()
        
        # Verify results
        expected_operations = num_threads * num_operations
        assert results['success'] == expected_operations, f"Expected {expected_operations} success, got {results['success']}. Errors: {results['errors']}"
        assert len(results['errors']) == 0, f"Unexpected errors: {results['errors']}"

    def test_concurrent_keyword_operations(self, concurrent_csv_app):
        """Test concurrent keyword add operations."""
        num_threads = 10
        keywords_per_thread = 20
        results = {'success': 0, 'errors': []}
        
        def worker(thread_id):
            """Worker function for concurrent keyword operations."""
            try:
                for i in range(keywords_per_thread):
                    keyword = f"malicious_keyword_{thread_id}_{i}"
                    
                    # Add keyword
                    add_keyword(keyword)
                    results['success'] += 1
                    
                    # Small random delay
                    time.sleep(random.uniform(0.001, 0.002))
                        
            except Exception as e:
                results['errors'].append(f"Thread {thread_id}: {str(e)}")
        
        # Run concurrent operations
        threads = []
        for i in range(num_threads):
            thread = threading.Thread(target=worker, args=(i,))
            threads.append(thread)
            thread.start()
        
        # Wait for completion
        for thread in threads:
            thread.join()
        
        # Verify results
        expected_operations = num_threads * keywords_per_thread
        assert results['success'] == expected_operations, f"Expected {expected_operations} success, got {results['success']}. Errors: {results['errors']}"
        assert len(results['errors']) == 0, f"Unexpected errors: {results['errors']}"

    def test_mixed_concurrent_operations(self, concurrent_csv_app):
        """Test mixed concurrent operations across all CSV files."""
        num_operations = 100
        results = {'allowlist': 0, 'blocklist': 0, 'keywords': 0, 'errors': []}
        
        def allowlist_worker():
            """Worker for allowlist operations."""
            try:
                for i in range(num_operations):
                    ip = f"192.168.100.{i}"
                    add_ip_allowlist(ip)
                    if is_ip_allowlisted(ip):
                        results['allowlist'] += 1
                    time.sleep(random.uniform(0.001, 0.003))
            except Exception as e:
                results['errors'].append(f"Allowlist worker: {str(e)}")
        
        def blocklist_worker():
            """Worker for blocklist operations."""
            try:
                for i in range(num_operations):
                    ip = f"10.0.100.{i}"
                    add_ip_blocklist(ip, "Concurrent test")
                    if is_ip_blocklisted(ip):
                        results['blocklist'] += 1
                    time.sleep(random.uniform(0.001, 0.003))
            except Exception as e:
                results['errors'].append(f"Blocklist worker: {str(e)}")
        
        def keyword_worker():
            """Worker for keyword operations."""
            try:
                for i in range(num_operations):
                    keyword = f"concurrent_keyword_{i}"
                    add_keyword(keyword)
                    results['keywords'] += 1
                    time.sleep(random.uniform(0.001, 0.003))
            except Exception as e:
                results['errors'].append(f"Keyword worker: {str(e)}")
        
        # Start all workers concurrently
        threads = [
            threading.Thread(target=allowlist_worker),
            threading.Thread(target=blocklist_worker),
            threading.Thread(target=keyword_worker)
        ]
        
        for thread in threads:
            thread.start()
        
        for thread in threads:
            thread.join()
        
        # Verify all operations completed successfully
        assert results['allowlist'] == num_operations, f"Allowlist operations: expected {num_operations}, got {results['allowlist']}"
        assert results['blocklist'] == num_operations, f"Blocklist operations: expected {num_operations}, got {results['blocklist']}"
        assert results['keywords'] == num_operations, f"Keyword operations: expected {num_operations}, got {results['keywords']}"
        assert len(results['errors']) == 0, f"Unexpected errors: {results['errors']}"

    def test_high_contention_scenario(self, concurrent_csv_app):
        """Test high contention scenario with many threads hitting same operations."""
        num_threads = 50
        operations_per_thread = 10
        results = {'duplicates_handled': 0, 'errors': []}
        
        def worker(thread_id):
            """Worker that tries to add the same IPs (testing duplicate handling)."""
            with concurrent_csv_app.app_context():
                try:
                    for i in range(operations_per_thread):
                        # All threads try to add the same set of IPs
                        ip = f"192.168.255.{i % 5}"  # Only 5 unique IPs
                        
                        add_ip_allowlist(ip)
                        results['duplicates_handled'] += 1
                        
                        # Brief delay to increase contention
                        time.sleep(random.uniform(0.0001, 0.001))
                        
                except Exception as e:
                    results['errors'].append(f"Thread {thread_id}: {str(e)}")
        
        # Start high contention scenario
        with concurrent.futures.ThreadPoolExecutor(max_workers=num_threads) as executor:
            futures = [executor.submit(worker, i) for i in range(num_threads)]
            concurrent.futures.wait(futures)
        
        # Verify no errors occurred despite high contention
        assert len(results['errors']) == 0, f"Errors during high contention: {results['errors']}"
        
        # Verify only unique IPs were actually stored (check within app context)
        with concurrent_csv_app.app_context():
            unique_ips = set()
            for i in range(5):
                ip = f"192.168.255.{i}"
                if is_ip_allowlisted(ip):
                    unique_ips.add(ip)
            
            assert len(unique_ips) == 5, f"Expected 5 unique IPs, found {len(unique_ips)}"

    def test_file_integrity_under_load(self, concurrent_csv_app):
        """Test that CSV files maintain integrity under load."""
        num_threads = 20
        operations_per_thread = 25
        
        def worker(thread_id):
            """Worker that performs various operations."""
            for i in range(operations_per_thread):
                try:
                    with concurrent_csv_app.app_context():
                        # Allowlist operation
                        ip_white = f"172.16.{thread_id}.{i}"
                        add_ip_allowlist(ip_white)

                        # Blocklist operation
                        ip_black = f"172.17.{thread_id}.{i}"
                        add_ip_blocklist(ip_black, f"Test from thread {thread_id}")

                        # Keyword operation
                        keyword = f"test_keyword_{thread_id}_{i}"
                        add_keyword(keyword)

                    # Small delay
                    time.sleep(random.uniform(0.0005, 0.002))
                    
                except Exception as e:
                    pytest.fail(f"Thread {thread_id} failed: {e}")
        
        # Run load test
        threads = []
        for i in range(num_threads):
            thread = threading.Thread(target=worker, args=(i,))
            threads.append(thread)
            thread.start()
        
        for thread in threads:
            thread.join()
        
        # Verify file integrity by checking CSV files can be read
        data_dir = Path(_get_data_dir())
        
        # Check allowlist file
        allowlist_file = data_dir / "whitelist.csv"
        assert allowlist_file.exists(), "Allowlist CSV file missing"
        
        with open(allowlist_file, 'r') as f:
            lines = f.readlines()
            assert len(lines) > 1, "Allowlist file appears corrupted"
            assert 'ip,added_date' in lines[0], "Allowlist header corrupted"
        
        # Check blocklist file
        blocklist_file = data_dir / "blacklist.csv"
        assert blocklist_file.exists(), "Blocklist CSV file missing"
        
        with open(blocklist_file, 'r') as f:
            lines = f.readlines()
            assert len(lines) > 1, "Blocklist file appears corrupted"
            assert lines[0].strip().split(",") == CSV_HEADERS[BLOCKLIST_CSV], "Blocklist header corrupted"
        
        # Check keywords file
        keywords_file = data_dir / "keywords.csv"
        assert keywords_file.exists(), "Keywords CSV file missing"
        
        with open(keywords_file, 'r') as f:
            lines = f.readlines()
            assert len(lines) > 1, "Keywords file appears corrupted"
            assert 'keyword,added_date' in lines[0], "Keywords header corrupted"

    def test_performance_under_concurrent_load(self, concurrent_csv_app):
        """Test performance characteristics under concurrent load."""
        num_threads = 30
        operations_per_thread = 20
        start_time = time.time()
        
        def worker(thread_id):
            """Performance test worker."""
            for i in range(operations_per_thread):
                ip = f"10.{thread_id}.{i}.100"
                add_ip_blocklist(ip, "Performance test")
                assert is_ip_blocklisted(ip), f"IP {ip} not found immediately after adding"
        
        # Run performance test
        threads = []
        for i in range(num_threads):
            thread = threading.Thread(target=worker, args=(i,))
            threads.append(thread)
            thread.start()
        
        for thread in threads:
            thread.join()
        
        total_time = time.time() - start_time
        if total_time <= 0:
            total_time = 1e-6
        total_operations = num_threads * operations_per_thread * 2  # add + check
        ops_per_second = total_operations / total_time
        
        # Performance should be reasonable (adjust threshold as needed)
        assert ops_per_second > 100, f"Performance too slow: {ops_per_second:.2f} ops/sec"
        print(f"Concurrent performance: {ops_per_second:.2f} operations/second")
