#!/usr/bin/env python3
"""
AIWAF Django Test Infrastructure Validation

This script validates that the Django test infrastructure is working correctly.
"""

import os
import sys
import subprocess

def validate_django_setup():
    """Validate Django setup"""
    print("🔧 Validating Django Test Setup...")
    
    try:
        # Add project to path
        project_root = os.path.dirname(os.path.abspath(__file__))
        sys.path.insert(0, project_root)
        
        # Set Django settings
        os.environ.setdefault('DJANGO_SETTINGS_MODULE', 'tests.test_settings')
        
        # Try to import Django
        import django
        django.setup()
        
        print("✅ Django setup successful")
        return True
        
    except Exception as e:
        print(f"❌ Django setup failed: {e}")
        return False

def validate_base_classes():
    """Validate base test classes"""
    print("🧪 Validating Base Test Classes...")
    
    try:
        from tests.base_test import (
            AIWAFTestCase, 
            AIWAFMiddlewareTestCase, 
            AIWAFStorageTestCase, 
            AIWAFTrainerTestCase
        )
        
        print("✅ All base test classes imported successfully")
        return True
        
    except Exception as e:
        print(f"❌ Base class import failed: {e}")
        return False

def validate_test_settings():
    """Validate test settings"""
    print("⚙️  Validating Test Settings...")
    
    try:
        from django.conf import settings
        
        # Check key settings
        assert hasattr(settings, 'DATABASES')
        assert hasattr(settings, 'INSTALLED_APPS')
        assert 'aiwaf' in settings.INSTALLED_APPS
        assert hasattr(settings, 'AIWAF_SETTINGS')
        
        print("✅ Test settings configured correctly")
        return True
        
    except Exception as e:
        print(f"❌ Test settings validation failed: {e}")
        return False

def run_sample_test():
    """Run a sample test to validate the infrastructure"""
    print("🧪 Running Sample Test...")
    
    try:
        # Run the basic import test
        result = subprocess.run([
            sys.executable, 'manage.py', 'test', 'tests.test_basic_import_django', '-v', '0'
        ], capture_output=True, text=True, cwd=os.path.dirname(os.path.abspath(__file__)))
        
        if result.returncode == 0:
            print("✅ Sample test executed successfully")
            return True
        else:
            print(f"❌ Sample test failed: {result.stderr}")
            return False
            
    except Exception as e:
        print(f"❌ Sample test execution failed: {e}")
        return False

def count_test_files():
    """Count converted test files"""
    print("📊 Counting Test Files...")
    
    test_dir = os.path.dirname(os.path.abspath(__file__))
    django_tests = [f for f in os.listdir(test_dir) if f.endswith('_django.py')]
    
    print(f"✅ Found {len(django_tests)} Django unit test files")
    return len(django_tests)

def main():
    """Main validation function"""
    print("🚀 AIWAF Django Test Infrastructure Validation")
    print("=" * 60)
    
    validation_steps = [
        ("Django Setup", validate_django_setup),
        ("Base Classes", validate_base_classes),
        ("Test Settings", validate_test_settings),
        ("Test File Count", count_test_files),
    ]
    
    passed = 0
    total = len(validation_steps)
    
    for step_name, step_func in validation_steps:
        print(f"\n📋 {step_name}")
        print("-" * 40)
        
        try:
            result = step_func()
            if result:
                passed += 1
        except Exception as e:
            print(f"❌ {step_name} failed: {e}")
    
    # Summary
    print(f"\n🎯 Validation Summary")
    print("=" * 40)
    print(f"✅ Passed: {passed}/{total} validation steps")
    
    if passed == total:
        print("\n🎉 DJANGO TEST INFRASTRUCTURE IS READY!")
        print("\n📋 You can now run:")
        print("   python manage.py test")
        print("   python run_tests.py")
        print("\n🔧 Individual test files:")
        print("   python manage.py test tests.test_basic_import_django")
        print("   python manage.py test tests.test_header_validation_django")
        print("   python manage.py test tests.test_middleware_protection_django")
        
    else:
        print(f"\n⚠️  {total - passed} validation steps failed")
        print("Please review the errors above and fix any issues.")
    
    return passed == total

if __name__ == "__main__":
    success = main()
    sys.exit(0 if success else 1)