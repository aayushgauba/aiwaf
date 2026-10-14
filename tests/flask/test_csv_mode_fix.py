#!/usr/bin/env python3
"""
Test script to verify AIWAF CSV mode works correctly
"""

from flask import Flask
from aiwaf.flask.middleware import register_aiwaf_middlewares
from aiwaf.flask.storage import _get_storage_mode

def test_csv_mode():
    """Test that CSV mode is properly detected."""
    
    app = Flask(__name__)
    
    # Explicitly set CSV mode
    app.config['AIWAF_USE_CSV'] = True
    app.config['AIWAF_DATA_DIR'] = 'test_aiwaf_data'
    
    with app.app_context():
        storage_mode = _get_storage_mode()
        print(f"Storage mode: {storage_mode}")
        assert storage_mode == 'csv', f"Expected 'csv', got '{storage_mode}'"
    
    # Register middlewares (should not fail)
    register_aiwaf_middlewares(app, use_database=False)
    
    print(" CSV mode test passed!")
    
    # Test a simple request
    with app.test_client() as client:
        with app.test_request_context('/'):
            # This should work without database errors
            from aiwaf.flask.storage import is_ip_blocklisted
            result = is_ip_blocklisted('127.0.0.1')
            print(f"IP blocklist check: {result}")
    
    print(" All tests passed - AIWAF CSV mode working correctly!")

if __name__ == "__main__":
    test_csv_mode()