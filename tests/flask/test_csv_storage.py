import pytest
import tempfile
import shutil
import csv
import os
from pathlib import Path
from aiwaf.core.storage_schema import BLOCKLIST_CSV, CSV_HEADERS
from aiwaf.flask.storage import (
    add_ip_allowlist, is_ip_allowlisted,
    add_ip_blocklist, is_ip_blocklisted, remove_ip_blocklist,
    add_keyword, get_keyword_store, _get_storage_mode
)

@pytest.fixture
def csv_app():
    """Create Flask app configured for CSV storage."""
    from flask import Flask
    
    app = Flask(__name__)
    app.config['TESTING'] = True
    app.config['AIWAF_USE_CSV'] = True
    
    # Create temporary directory for CSV files
    temp_dir = tempfile.mkdtemp()
    app.config['AIWAF_DATA_DIR'] = temp_dir
    
    yield app
    
    # Cleanup
    shutil.rmtree(temp_dir, ignore_errors=True)

@pytest.fixture
def csv_app_context(csv_app):
    """Create application context for CSV storage."""
    with csv_app.app_context():
        yield csv_app

def test_csv_storage_mode_detection(csv_app_context):
    """Test that CSV storage mode is detected correctly."""
    assert _get_storage_mode() == 'csv'

def test_csv_allowlist_operations(csv_app_context):
    """Test CSV allowlist add and check operations."""
    ip = '192.168.1.100'
    
    # Initially not allowlisted
    assert not is_ip_allowlisted(ip)
    
    # Add to allowlist
    add_ip_allowlist(ip)
    assert is_ip_allowlisted(ip)
    
    # Check CSV file was created and contains the IP
    data_dir = Path(csv_app_context.config['AIWAF_DATA_DIR'])
    allowlist_file = data_dir / 'whitelist.csv'
    assert allowlist_file.exists()
    
    with open(allowlist_file, 'r') as f:
        content = f.read()
        assert ip in content

def test_csv_blocklist_operations(csv_app_context):
    """Test CSV blocklist add, check, and remove operations."""
    ip = '10.0.0.1'
    reason = 'Test blocking'
    
    # Initially not blocklisted
    assert not is_ip_blocklisted(ip)
    
    # Add to blocklist
    add_ip_blocklist(ip, reason)
    assert is_ip_blocklisted(ip)
    
    # Check CSV file was created and contains the IP
    data_dir = Path(csv_app_context.config['AIWAF_DATA_DIR'])
    blocklist_file = data_dir / 'blacklist.csv'
    assert blocklist_file.exists()
    
    with open(blocklist_file, 'r') as f:
        content = f.read()
        assert ip in content
        assert reason in content
    
    # Remove from blocklist
    remove_ip_blocklist(ip)
    assert not is_ip_blocklisted(ip)

def test_csv_keyword_operations(csv_app_context):
    """Test CSV keyword add and retrieval operations."""
    keyword = 'malicious'
    
    # Add keyword
    add_keyword(keyword)
    
    # Check keyword store
    keyword_store = get_keyword_store()
    assert keyword in keyword_store.get_top_keywords()
    
    # Check CSV file was created and contains the keyword
    data_dir = Path(csv_app_context.config['AIWAF_DATA_DIR'])
    keywords_file = data_dir / 'keywords.csv'
    assert keywords_file.exists()
    
    with open(keywords_file, 'r') as f:
        content = f.read()
        assert keyword in content

def test_csv_file_creation(csv_app_context):
    """Test that CSV files are created with proper headers."""
    data_dir = Path(csv_app_context.config['AIWAF_DATA_DIR'])
    
    # Trigger file creation by adding data
    add_ip_allowlist('1.1.1.1')
    add_ip_blocklist('2.2.2.2', 'test')
    add_keyword('test')
    
    # Check allowlist file
    allowlist_file = data_dir / 'whitelist.csv'
    with open(allowlist_file, 'r') as f:
        reader = csv.reader(f)
        headers = next(reader)
        assert headers == ['ip', 'added_date']
    
    # Check blocklist file
    blocklist_file = data_dir / 'blacklist.csv'
    with open(blocklist_file, 'r') as f:
        reader = csv.reader(f)
        headers = next(reader)
        assert headers == CSV_HEADERS[BLOCKLIST_CSV]
    
    # Check keywords file
    keywords_file = data_dir / 'keywords.csv'
    with open(keywords_file, 'r') as f:
        reader = csv.reader(f)
        headers = next(reader)
        assert headers == ['keyword', 'added_date']

def test_csv_duplicate_handling(csv_app_context):
    """Test that duplicates are handled properly in CSV storage."""
    ip = '192.168.1.200'
    
    # Add same IP multiple times
    add_ip_allowlist(ip)
    add_ip_allowlist(ip)
    add_ip_allowlist(ip)
    
    # Should still only appear once
    data_dir = Path(csv_app_context.config['AIWAF_DATA_DIR'])
    allowlist_file = data_dir / 'whitelist.csv'
    
    with open(allowlist_file, 'r') as f:
        content = f.read()
        # Count occurrences of IP (excluding header)
        ip_count = content.count(ip)
        assert ip_count == 1

def test_csv_persistence_across_operations(csv_app_context):
    """Test that CSV data persists across multiple operations."""
    # Add multiple IPs
    ips = ['192.168.1.1', '192.168.1.2', '192.168.1.3']
    for ip in ips:
        add_ip_allowlist(ip)
    
    # Check all are present
    for ip in ips:
        assert is_ip_allowlisted(ip)
    
    # Verify data persists by checking file directly
    data_dir = Path(csv_app_context.config['AIWAF_DATA_DIR'])
    allowlist_file = data_dir / 'whitelist.csv'
    assert allowlist_file.exists()
    
    with open(allowlist_file, 'r') as f:
        content = f.read()
        for ip in ips:
            assert ip in content

def test_csv_keyword_store_functionality(csv_app_context):
    """Test keyword store functionality with CSV backend."""
    keywords = ['malicious', 'attack', 'exploit', 'hack']
    
    # Add keywords
    for keyword in keywords:
        add_keyword(keyword)
    
    # Get keyword store
    keyword_store = get_keyword_store()
    
    # Test get_top_keywords
    top_keywords = keyword_store.get_top_keywords(2)
    assert len(top_keywords) == 2
    for kw in top_keywords:
        assert kw in keywords
    
    # Test all keywords
    all_keywords = keyword_store.get_top_keywords(10)
    for keyword in keywords:
        assert keyword in all_keywords

def test_csv_error_handling(csv_app_context):
    """Test error handling for CSV operations."""
    # Test with invalid directory permissions (if possible)
    data_dir = Path(csv_app_context.config['AIWAF_DATA_DIR'])
    
    # Create a file with same name as expected directory
    invalid_file = data_dir / 'whitelist.csv'
    invalid_file.parent.mkdir(exist_ok=True)
    
    # Try operations that should handle errors gracefully
    try:
        add_ip_allowlist('192.168.1.1')
        is_ip_allowlisted('192.168.1.1')
        # Should not raise exceptions
    except Exception as e:
        pytest.fail(f"CSV operations should handle errors gracefully: {e}")

def test_csv_concurrent_access(csv_app_context):
    """Test concurrent access to CSV files with improved locking."""
    import threading
    import time
    import random
    
    num_threads = 10
    operations_per_thread = 5
    results = {'success': 0, 'errors': []}
    
    def worker(thread_id):
        """Worker function for concurrent testing."""
        try:
            for i in range(operations_per_thread):
                # Each thread works with unique IPs
                ip = f"10.10.{thread_id}.{i}"
                
                # Add to allowlist
                add_ip_allowlist(ip)
                
                # Small delay to create some contention
                time.sleep(random.uniform(0.001, 0.005))
                
                # Verify it was added
                if is_ip_allowlisted(ip):
                    results['success'] += 1
                else:
                    results['errors'].append(f"Thread {thread_id}: IP {ip} not found")
                    
        except Exception as e:
            results['errors'].append(f"Thread {thread_id}: Exception {e}")
    
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
    expected_success = num_threads * operations_per_thread
    assert results['success'] == expected_success, f"Expected {expected_success}, got {results['success']}. Errors: {results['errors']}"
    assert len(results['errors']) == 0, f"Unexpected errors: {results['errors']}"
