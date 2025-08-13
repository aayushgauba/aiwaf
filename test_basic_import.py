#!/usr/bin/env python3
"""
Minimal AI-WAF Import Test
This script tests basic AI-WAF imports without requiring full dependencies.
"""

def test_basic_aiwaf_import():
    """Test that AI-WAF can be imported safely during Django app loading."""
    print("🧪 Testing Basic AI-WAF Import")
    print("=" * 40)
    
    # 1. Test basic import
    try:
        import aiwaf
        print(f"✅ Basic import successful (version: {aiwaf.__version__})")
    except Exception as e:
        print(f"❌ Basic import failed: {e}")
        return False
    
    # 2. Test module availability (without importing everything)
    try:
        import aiwaf.middleware
        print("✅ Middleware module accessible")
    except Exception as e:
        print(f"❌ Middleware module import failed: {e}")
        return False
    
    # 3. Test storage import (the problematic one)
    try:
        import aiwaf.storage
        print("✅ Storage module imported successfully")
    except Exception as e:
        print(f"❌ Storage import failed: {e}")
        return False
    
    # 4. Test trainer import (had settings access issue)
    try:
        import aiwaf.trainer
        print("✅ Trainer module imported successfully")
    except Exception as e:
        print(f"❌ Trainer import failed: {e}")
        return False
    
    # 5. Test utils import
    try:
        import aiwaf.utils
        print("✅ Utils module imported successfully")
    except Exception as e:
        print(f"❌ Utils import failed: {e}")
        return False
    
    print("\n🎉 All basic imports successful!")
    print("The AppRegistryNotReady and AttributeError issues should be fixed.")
    return True

if __name__ == "__main__":
    success = test_basic_aiwaf_import()
    if success:
        print("\n💡 You can now run:")
        print("  python manage.py check")
        print("  python manage.py migrate")
        print("  python manage.py runserver")
        print("\n📦 To install with all dependencies:")
        print("  pip install --upgrade aiwaf")
    else:
        print("\n⚠️  Some issues remain. Please check the error messages above.")
