#!/usr/bin/env python3
"""
AI-WAF Debug Helper Script
Run this script to diagnose AI-WAF installation issues.
"""

def check_aiwaf_installation():
    """Check AI-WAF installation and provide debugging information."""
    print("🔍 AI-WAF Installation Check")
    print("=" * 40)
    
    # 1. Check Python version
    import sys
    print(f"Python Version: {sys.version}")
    print()
    
    # 2. Check AI-WAF import
    try:
        import aiwaf
        version = getattr(aiwaf, '__version__', 'Unknown')
        print(f"✅ AI-WAF imported successfully (version: {version})")
        
        # Test critical imports that caused AppRegistryNotReady
        try:
            from aiwaf import storage, utils, trainer
            print("✅ Critical modules (storage, utils, trainer) imported successfully")
        except Exception as e:
            print(f"❌ Critical module import failed: {e}")
            print("   This may indicate the AppRegistryNotReady issue persists")
            
    except ImportError as e:
        print(f"❌ AI-WAF import failed: {e}")
        print("   Solution: Run 'pip install aiwaf' or 'pip install --upgrade aiwaf'")
        return False
    
    # 3. Check Django availability
    try:
        import django
        print(f"✅ Django available (version: {django.get_version()})")
    except ImportError:
        print("❌ Django not available")
        print("   Solution: Run 'pip install Django'")
        return False
    
    # 4. Check if in Django project
    try:
        from django.conf import settings
        if settings.configured:
            print("✅ Django settings configured")
        else:
            print("⚠️  Django settings not configured")
            print("   Info: This is normal outside of a Django project")
    except:
        print("⚠️  Cannot access Django settings")
        print("   Info: This is normal outside of a Django project")
    
    # 5. Check middleware imports
    print("\n🧱 Middleware Import Check:")
    middleware_classes = [
        'IPAndKeywordBlockMiddleware',
        'RateLimitMiddleware', 
        'AIAnomalyMiddleware',
        'HoneypotTimingMiddleware',
        'UUIDTamperMiddleware'
    ]
    
    try:
        from aiwaf import middleware
        for cls_name in middleware_classes:
            if hasattr(middleware, cls_name):
                print(f"  ✅ {cls_name}")
            else:
                print(f"  ❌ {cls_name} (not found)")
    except ImportError as e:
        print(f"  ❌ Could not import aiwaf.middleware: {e}")
    
    # 6. Direct middleware module check
    print("\n🔧 Direct Module Check:")
    try:
        import aiwaf.middleware as mw
        available = [name for name in dir(mw) if not name.startswith('_') and 'Middleware' in name]
        print(f"  Available middleware classes: {available}")
    except Exception as e:
        print(f"  ❌ Error: {e}")
    
    print("\n💡 Common Solutions:")
    print("1. Update AI-WAF: pip install --upgrade aiwaf")
    print("2. In Django project, add 'aiwaf' to INSTALLED_APPS")
    print("3. Run Django migration: python manage.py migrate")
    print("4. Use diagnostic command: python manage.py aiwaf_diagnose")
    
    return True

if __name__ == "__main__":
    check_aiwaf_installation()
