#!/usr/bin/env python3

import os
import sys
import django
from django.conf import settings

# Add the current directory to Python path
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

# Configure Django settings
if not settings.configured:
    settings.configure(
        DEBUG=True,
        SECRET_KEY='test-secret-key-for-aiwaf-testing-only',
        INSTALLED_APPS=[
            'django.contrib.admin',
            'django.contrib.auth',
            'django.contrib.contenttypes',
            'django.contrib.sessions',
            'aiwaf',
        ],
        ROOT_URLCONF='test_include_urls',
        DATABASES={
            'default': {
                'ENGINE': 'django.db.backends.sqlite3',
                'NAME': ':memory:',
            }
        },
        AIWAF_ENABLED=True,
    )

# Setup Django
django.setup()

# Create a test URLs configuration that demonstrates the edge case
from django.urls import path, include
from django.http import HttpResponse

def dummy_view(request):
    return HttpResponse("OK")

def school_page_view(request):
    return HttpResponse("School page")

# Create pages app URLs (what would be in pages.urls)
pages_urlpatterns = [
    path('about/', dummy_view, name='school_about'),
    path('contact/', dummy_view, name='school_contact'),
    path('', school_page_view, name='school_home'),
]

# Main URL configuration with the edge case:
# path('school/', include('pages.urls')) where 'school' is NOT an actual Django app
test_urlpatterns = [
    path('admin/', dummy_view, name='admin'),
    path('school/', include(pages_urlpatterns)),  # This is the edge case!
    path('library/', include(pages_urlpatterns)),  # Another non-app include
    path('cafeteria/', include(pages_urlpatterns)),  # Another non-app include
    # Note: 'school', 'library', 'cafeteria' are NOT Django apps, just URL prefixes
]

# Create a simple test_include_urls module in memory
import types
test_urls_module = types.ModuleType('test_include_urls')
test_urls_module.urlpatterns = test_urlpatterns
sys.modules['test_include_urls'] = test_urls_module

def test_include_path_edge_case():
    """Test the edge case where path('school/', include('pages.urls')) 
    extracts 'school' as legitimate even though 'school' is not a Django app"""
    print("🧪 Testing Include Path Edge Case")
    print("=" * 60)
    
    from aiwaf.trainer import _extract_django_route_keywords, get_legitimate_keywords
    from django.apps import apps
    
    print("\n1. Checking current Django apps...")
    app_names = [app.name.split('.')[-1] for app in apps.get_app_configs()]
    print(f"   Installed Django apps: {app_names}")
    
    print("\n2. Testing route keyword extraction...")
    extracted_keywords = _extract_django_route_keywords()
    print(f"   Keywords extracted from routes: {sorted(extracted_keywords)}")
    
    # Check if non-app URL prefixes are being extracted
    url_prefixes_in_routes = ['school', 'library', 'cafeteria']
    problematic_extractions = []
    
    for prefix in url_prefixes_in_routes:
        if prefix in extracted_keywords:
            problematic_extractions.append(prefix)
            print(f"   ⚠️  '{prefix}' extracted as legitimate (but it's not a Django app)")
        else:
            print(f"   ✅ '{prefix}' NOT extracted (correct behavior)")
    
    print("\n3. Testing complete legitimate keywords...")
    all_legitimate = get_legitimate_keywords()
    
    for prefix in url_prefixes_in_routes:
        if prefix in all_legitimate:
            print(f"   ⚠️  '{prefix}' marked as legitimate keyword")
        else:
            print(f"   ✅ '{prefix}' NOT marked as legitimate")
    
    print(f"\n4. Edge case analysis:")
    if problematic_extractions:
        print(f"   ❌ ISSUE DETECTED: {problematic_extractions} are extracted as legitimate")
        print(f"      This means requests to /{problematic_extractions[0]}/malicious.php might not be flagged")
        print(f"      because '{problematic_extractions[0]}' is considered legitimate")
    else:
        print(f"   ✅ No issues detected")
    
    return problematic_extractions

def test_middleware_behavior_with_edge_case():
    """Test how the middleware behaves with the edge case"""
    print("\n🧪 Testing Middleware Behavior with Edge Case")
    print("=" * 60)
    
    from django.test import RequestFactory
    from aiwaf.middleware import IPAndKeywordBlockMiddleware
    from aiwaf.trainer import path_exists_in_django
    
    # Create middleware instance
    def dummy_get_response(request):
        return HttpResponse("OK")
    
    middleware = IPAndKeywordBlockMiddleware(dummy_get_response)
    factory = RequestFactory()
    
    # Test paths
    test_paths = [
        '/school/',  # Should exist and be allowed
        '/school/about/',  # Should exist and be allowed  
        '/school/malicious.php',  # Should NOT exist, but 'school' is in legitimate keywords
        '/library/hack.php',  # Should NOT exist, and 'library' might be flagged
        '/unknown/attack.php',  # Should NOT exist, 'unknown' should be flagged
    ]
    
    print("\n   Testing path existence:")
    for path in test_paths:
        exists = path_exists_in_django(path)
        print(f"   {path:<25} exists: {exists}")
    
    print("\n   Testing middleware legitimate keywords:")
    print(f"   Middleware legitimate keywords (first 20): {sorted(list(middleware.legitimate_path_keywords))[:20]}")
    
    # Check if problematic keywords are in middleware's legitimate set
    for keyword in ['school', 'library', 'cafeteria']:
        if keyword in middleware.legitimate_path_keywords:
            print(f"   ⚠️  '{keyword}' is in middleware legitimate keywords")
        else:
            print(f"   ✅ '{keyword}' NOT in middleware legitimate keywords")
    
    print("\n   Simulating requests:")
    for path in test_paths:
        request = factory.get(path)
        exists = path_exists_in_django(path)
        
        # Extract segments like middleware does
        import re
        segments = [seg for seg in re.split(r"\W+", path.lower()) if len(seg) > 3]
        
        legitimate_segments = [seg for seg in segments if seg in middleware.legitimate_path_keywords]
        suspicious_segments = [seg for seg in segments if seg not in middleware.legitimate_path_keywords]
        
        print(f"   {path:<25} | exists: {exists:<5} | legitimate: {legitimate_segments} | suspicious: {suspicious_segments}")

def suggest_fix():
    """Suggest a fix for the edge case"""
    print("\n💡 Suggested Fix for Edge Case")
    print("=" * 60)
    
    print("""
The issue is that _extract_django_route_keywords() extracts keywords from URL patterns
including include() paths, but it doesn't distinguish between:
1. Keywords from actual Django app names/models (legitimate)
2. Keywords from arbitrary URL path prefixes used with include() (potentially problematic)

SUGGESTED FIX:
Modify the keyword extraction logic to be more conservative about include() patterns.
Only extract keywords from include() patterns if they correspond to actual Django apps.

Here's the approach:
1. When processing URLResolver patterns (include() patterns), check if the path prefix
   corresponds to an actual Django app name
2. Only extract the keyword if it's an actual app name
3. For arbitrary path prefixes that aren't apps, don't automatically mark them as legitimate

This would prevent the false legitimization of keywords like 'school' when they're just
URL path prefixes and not actual Django apps.
""")

if __name__ == "__main__":
    try:
        # Run the tests
        problematic_extractions = test_include_path_edge_case()
        test_middleware_behavior_with_edge_case()
        suggest_fix()
        
        if problematic_extractions:
            print(f"\n❌ EDGE CASE CONFIRMED: {problematic_extractions} incorrectly marked as legitimate")
            print("   This could lead to missed malicious requests")
        else:
            print(f"\n✅ NO EDGE CASE DETECTED")
            
    except Exception as e:
        print(f"❌ Test failed with error: {e}")
        import traceback
        traceback.print_exc()
        sys.exit(1)
