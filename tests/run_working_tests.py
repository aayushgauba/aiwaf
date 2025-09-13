#!/usr/bin/env python3
"""
AIWAF Test Runner - Run Working Tests Only

This script runs the Django unit tests that are currently working,
skipping the ones that have dependency or import issues.
"""

import os
import sys
import subprocess

def run_working_tests():
    """Run the Django unit tests that are currently working"""
    
    print("🧪 Running AIWAF Working Django Unit Tests")
    print("=" * 50)
    
    # Tests that are currently working
    working_tests = [
        'tests.test_basic_import_django',
        'tests.test_aiwaf_reset_django',
        'tests.test_conservative_path_validation_django',
        'tests.test_csv_simple_django',
        'tests.test_edge_case_fix_demo_django', 
        'tests.test_exemption_simple_django',
        'tests.test_header_validation_django',
        'tests.test_honeypot_enhancements_django',
        'tests.test_import_fix_django',
        'tests.test_improved_path_validation_django',
        'tests.test_include_path_edge_case_django',
        'tests.test_keyword_persistence_django',
        'tests.test_keyword_protection_django',
        'tests.test_keyword_storage_debug_django',
        'tests.test_live_web_app_django',
        'tests.test_malicious_keywords_fix_django',
        'tests.test_method_validation_django',
        'tests.test_method_validation_simple_django',
        'tests.test_middleware_enhanced_validation_django',
        'tests.test_middleware_learning_fix_django',
        'tests.test_middleware_logger_django',
        'tests.test_middleware_protection_django',
        'tests.test_path_validation_flaw_django',
        'tests.test_rate_limiting_django',
        'tests.test_rate_limiting_pure_logic_django',
        'tests.test_real_world_headers_django',
        'tests.test_route_keyword_extraction_django',
        'tests.test_route_protection_simple_django',
        'tests.test_simplified_honeypot_django',
        'tests.test_storage_fix_django',
        'tests.test_storage_simple_django',
        'tests.test_trainer_enhancements_django',
        'tests.test_unified_keyword_logic_django',
        'tests.test_view_method_detection_django',
    ]
    
    total_tests = len(working_tests)
    passed_tests = 0
    failed_tests = []
    
    for i, test in enumerate(working_tests, 1):
        print(f"\n📋 Running test {i}/{total_tests}: {test}")
        print("-" * 60)
        
        try:
            result = subprocess.run([
                sys.executable, 'manage.py', 'test', test, '--verbosity=1'
            ], capture_output=True, text=True, timeout=30)
            
            if result.returncode == 0:
                print(f"✅ PASSED: {test}")
                passed_tests += 1
            else:
                print(f"❌ FAILED: {test}")
                print(f"Error: {result.stderr}")
                failed_tests.append(test)
                
        except subprocess.TimeoutExpired:
            print(f"⏰ TIMEOUT: {test}")
            failed_tests.append(test)
        except Exception as e:
            print(f"💥 ERROR: {test} - {e}")
            failed_tests.append(test)
    
    # Summary
    print(f"\n🎯 Test Results Summary")
    print("=" * 50)
    print(f"✅ Passed: {passed_tests}/{total_tests}")
    print(f"❌ Failed: {len(failed_tests)}/{total_tests}")
    
    if failed_tests:
        print(f"\n📋 Failed Tests:")
        for test in failed_tests:
            print(f"   - {test}")
    
    success_rate = (passed_tests / total_tests) * 100
    print(f"\n📊 Success Rate: {success_rate:.1f}%")
    
    if success_rate > 80:
        print("🎉 Excellent! Most tests are working!")
    elif success_rate > 60:
        print("👍 Good! Majority of tests are working!")
    else:
        print("⚠️  Need more work on test fixes")
    
    return passed_tests, failed_tests

if __name__ == "__main__":
    os.chdir(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
    passed, failed = run_working_tests()
    
    if len(failed) == 0:
        print("\n🎉 ALL WORKING TESTS PASSED!")
        sys.exit(0)
    else:
        print(f"\n⚠️  {len(failed)} tests need attention")
        sys.exit(1)