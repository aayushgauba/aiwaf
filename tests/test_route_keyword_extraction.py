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
        ROOT_URLCONF='test_urls',
        DATABASES={
            'default': {
                'ENGINE': 'django.db.backends.sqlite3',
                'NAME': ':memory:',
            }
        },
        AIWAF_ENABLED=True,
        AIWAF_ALLOWED_PATH_KEYWORDS=['special', 'custom'],
        AIWAF_EXEMPT_KEYWORDS=['exempt1', 'exempt2'],
    )

# Setup Django
django.setup()

# Create a test URLs configuration
from django.urls import path, include
from django.http import HttpResponse

def dummy_view(request):
    return HttpResponse("OK")

def profile_view(request):
    return HttpResponse("Profile")

def user_view(request, user_id):
    return HttpResponse(f"User {user_id}")

# Test URL patterns that should have their keywords extracted
test_urlpatterns = [
    path('admin/', dummy_view, name='admin'),
    path('profile/', profile_view, name='profile'),
    path('profiles/', dummy_view, name='profiles'),
    path('user/<int:user_id>/', user_view, name='user_detail'),
    path('users/', dummy_view, name='user_list'),
    path('accounts/', include([
        path('login/', dummy_view, name='login'),
        path('register/', dummy_view, name='register'),
    ])),
    path('api/v1/', include([
        path('posts/', dummy_view, name='api_posts'),
        path('comments/', dummy_view, name='api_comments'),
    ])),
    path('en/', include([
        path('profile/', profile_view, name='en_profile'),
        path('dashboard/', dummy_view, name='en_dashboard'),
    ])),
]

# Create a simple test_urls module in memory
import types
test_urls_module = types.ModuleType('test_urls')
test_urls_module.urlpatterns = test_urlpatterns
sys.modules['test_urls'] = test_urls_module

def test_route_keyword_extraction():
    """Test that Django route keywords are properly extracted and ignored"""
    print("🧪 Testing Route Keyword Extraction")
    print("=" * 50)
    
    # Import the enhanced trainer functions
    from aiwaf.trainer import get_legitimate_keywords, _extract_django_route_keywords
    
    print("\n1. Testing Django route keyword extraction...")
    django_keywords = _extract_django_route_keywords()
    print(f"   Extracted Django keywords: {sorted(django_keywords)}")
    
    print("\n2. Testing complete legitimate keywords set...")
    all_legitimate = get_legitimate_keywords()
    print(f"   Total legitimate keywords: {len(all_legitimate)}")
    print(f"   First 20 keywords: {sorted(list(all_legitimate))[:20]}")
    
    print("\n3. Checking specific keywords that should be legitimate...")
    expected_legitimate = ['profile', 'user', 'users', 'admin', 'api', 'accounts', 'login', 'register', 'posts', 'comments', 'dashboard']
    for keyword in expected_legitimate:
        if keyword in all_legitimate:
            print(f"   ✅ '{keyword}' correctly identified as legitimate")
        else:
            print(f"   ❌ '{keyword}' NOT found in legitimate keywords")
    
    print("\n4. Testing settings-based keywords...")
    print(f"   AIWAF_ALLOWED_PATH_KEYWORDS: {getattr(settings, 'AIWAF_ALLOWED_PATH_KEYWORDS', [])}")
    print(f"   AIWAF_EXEMPT_KEYWORDS: {getattr(settings, 'AIWAF_EXEMPT_KEYWORDS', [])}")
    
    for keyword in ['special', 'custom', 'exempt1', 'exempt2']:
        if keyword in all_legitimate:
            print(f"   ✅ Settings keyword '{keyword}' correctly included")
        else:
            print(f"   ❌ Settings keyword '{keyword}' NOT found")
    
    print("\n5. Testing app and model extraction...")
    from django.apps import apps
    for app_config in apps.get_app_configs():
        app_name = app_config.name.split('.')[-1]  # Get just the app name
        if app_name in all_legitimate:
            print(f"   ✅ App '{app_name}' keywords included")
    
    print("\n" + "=" * 50)
    print("✅ Route keyword extraction test completed!")
    return all_legitimate

def test_keyword_learning_with_routes():
    """Test that legitimate route keywords are not learned as suspicious"""
    print("\n🧪 Testing Keyword Learning with Route Protection")
    print("=" * 50)
    
    from aiwaf.trainer import get_legitimate_keywords
    import re
    from collections import Counter
    
    # Simulate suspicious log entries that contain legitimate route keywords
    fake_log_entries = [
        {"path": "/profile/hack.php", "status": "404"},  # profile is legitimate
        {"path": "/user/12345/shell.php", "status": "404"},  # user is legitimate
        {"path": "/admin/xmlrpc.php", "status": "404"},  # admin is legitimate
        {"path": "/api/v1/exploit.php", "status": "404"},  # api is legitimate
        {"path": "/malicious/unknown/badword.php", "status": "404"},  # malicious, unknown, badword should be learned
        {"path": "/accounts/login/hack", "status": "404"},  # accounts, login legitimate
        {"path": "/evilkeyword/test.php", "status": "500"},  # evilkeyword should be learned
    ]
    
    legitimate_keywords = get_legitimate_keywords()
    print(f"   Legitimate keywords to protect: {len(legitimate_keywords)}")
    
    # Simulate keyword extraction logic from trainer
    tokens = Counter()
    STATIC_KW = [".php", "xmlrpc", "wp-", ".env", ".git", ".bak", "conflg", "shell", "filemanager"]
    
    for entry in fake_log_entries:
        if entry["status"].startswith(("4", "5")):  # Error status
            for seg in re.split(r"\W+", entry["path"].lower()):
                if (len(seg) > 3 and 
                    seg not in STATIC_KW and 
                    seg not in legitimate_keywords):  # This is the key protection
                    tokens[seg] += 1
    
    print("\n   Keywords that would be learned as suspicious:")
    for keyword, count in tokens.most_common():
        print(f"     - '{keyword}': {count} occurrences")
    
    # Check that legitimate keywords were NOT learned
    legitimate_found_in_suspicious = []
    for keyword in ['profile', 'user', 'admin', 'api', 'accounts', 'login']:
        if keyword in tokens:
            legitimate_found_in_suspicious.append(keyword)
    
    if legitimate_found_in_suspicious:
        print(f"   ❌ ERROR: Legitimate keywords learned as suspicious: {legitimate_found_in_suspicious}")
    else:
        print("   ✅ SUCCESS: No legitimate keywords learned as suspicious")
    
    # Check that truly malicious keywords WERE learned
    expected_malicious = ['malicious', 'unknown', 'badword', 'evilkeyword']
    malicious_learned = [kw for kw in expected_malicious if kw in tokens]
    
    print(f"   Expected malicious keywords learned: {malicious_learned}")
    
    print("\n" + "=" * 50)
    print("✅ Keyword learning protection test completed!")

if __name__ == "__main__":
    try:
        # Run the tests
        legitimate_keywords = test_route_keyword_extraction()
        test_keyword_learning_with_routes()
        
        print(f"\n🎉 ALL TESTS COMPLETED!")
        print(f"📊 Total legitimate keywords protected: {len(legitimate_keywords)}")
        
    except Exception as e:
        print(f"❌ Test failed with error: {e}")
        import traceback
        traceback.print_exc()
        sys.exit(1)
