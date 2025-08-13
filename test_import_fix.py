#!/usr/bin/env python3
"""
Test AI-WAF Import Fix
This script tests that AI-WAF can be imported without AppRegistryNotReady errors.
"""

def test_aiwaf_import():
    """Test that AI-WAF can be imported safely during Django app loading."""
    print("🧪 Testing AI-WAF Import Fix")
    print("=" * 40)
    
    # 1. Test basic import
    try:
        import aiwaf
        print(f"✅ Basic import successful (version: {aiwaf.__version__})")
    except Exception as e:
        print(f"❌ Basic import failed: {e}")
        return False
    
    # 2. Test middleware import
    try:
        from aiwaf import middleware
        print("✅ Middleware module imported successfully")
        
        # Check middleware classes are available
        middleware_classes = [
            'IPAndKeywordBlockMiddleware',
            'RateLimitMiddleware', 
            'AIAnomalyMiddleware',
            'HoneypotTimingMiddleware',
            'UUIDTamperMiddleware'
        ]
        
        for cls_name in middleware_classes:
            if hasattr(middleware, cls_name):
                print(f"  ✅ {cls_name}")
            else:
                print(f"  ❌ {cls_name} (missing)")
                
    except Exception as e:
        print(f"❌ Middleware import failed: {e}")
        return False
    
    # 3. Test storage import (the problematic one)
    try:
        from aiwaf import storage
        print("✅ Storage module imported successfully")
    except Exception as e:
        print(f"❌ Storage import failed: {e}")
        return False
    
    # 4. Test trainer import (which imports utils -> storage)
    try:
        from aiwaf import trainer
        print("✅ Trainer module imported successfully")
    except Exception as e:
        print(f"❌ Trainer import failed: {e}")
        return False
    
    # 5. Test utils import
    try:
        from aiwaf import utils
        print("✅ Utils module imported successfully")
    except Exception as e:
        print(f"❌ Utils import failed: {e}")
        return False
    
    print("\n🎉 All imports successful!")
    print("The AppRegistryNotReady error should be fixed.")
    return True

if __name__ == "__main__":
    success = test_aiwaf_import()
    if success:
        print("\n💡 You can now run:")
        print("  python manage.py check")
        print("  python manage.py migrate")
        print("  python manage.py runserver")
    else:
        print("\n⚠️  Some issues remain. Please check the error messages above.")
