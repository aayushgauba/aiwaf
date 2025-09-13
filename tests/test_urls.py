"""
Test URLs for AIWAF unit tests
"""

from django.urls import path
from django.http import HttpResponse

def test_view(request):
    """Simple test view"""
    return HttpResponse("Test response")

def test_post_view(request):
    """Test POST view"""
    if request.method == 'POST':
        return HttpResponse("POST response")
    return HttpResponse("GET response")

def test_protected_view(request):
    """Test protected view for middleware testing"""
    return HttpResponse("Protected content")

urlpatterns = [
    path('test/', test_view, name='test'),
    path('test-post/', test_post_view, name='test_post'),
    path('protected/', test_protected_view, name='protected'),
    path('admin/login/', test_view, name='admin_login'),
    path('api/users/', test_view, name='api_users'),
]