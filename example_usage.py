# Example usage of the @aiwaf_exempt decorator

from django.shortcuts import render
from django.http import JsonResponse
from aiwaf.decorators import aiwaf_exempt

# Example 1: Function-based view with decorator
@aiwaf_exempt
def my_api_view(request):
    """This view will be exempt from all AI-WAF protection"""
    return JsonResponse({"status": "success"})

# Example 2: Function-based view without decorator 
def protected_view(request):
    """This view will be protected by AI-WAF"""
    return render(request, "protected.html")

# Example 3: Class-based view with decorator
from django.views import View

@aiwaf_exempt
class MyAPIView(View):
    """This entire view class will be exempt from AI-WAF protection"""
    
    def get(self, request):
        return JsonResponse({"method": "GET"})
    
    def post(self, request):
        return JsonResponse({"method": "POST"})

# Example 4: Class-based view without decorator
class ProtectedView(View):
    """This view class will be protected by AI-WAF"""
    
    def get(self, request):
        return render(request, "protected.html")

# Example URLs configuration
"""
# In your urls.py:

from django.urls import path
from . import views

urlpatterns = [
    path('api/exempt/', views.my_api_view, name='exempt-api'),
    path('api/protected/', views.protected_view, name='protected-view'),
    path('class/exempt/', views.MyAPIView.as_view(), name='exempt-class'),
    path('class/protected/', views.ProtectedView.as_view(), name='protected-class'),
]
"""

# How the exemption system works:
"""
1. When a request comes in, the middleware checks:
   - Is the IP address in the IPExemption model? -> Allow
   - Is the path in AIWAF_EXEMPT_PATHS setting? -> Allow  
   - Does the view function have aiwaf_exempt=True attribute? -> Allow
   - Otherwise -> Apply normal WAF protection

2. The @aiwaf_exempt decorator simply sets view_func.aiwaf_exempt = True

3. The middleware uses utils.is_exempt(request) which checks all exemption methods

4. This provides multiple layers of exemption:
   - Global IP exemptions (via management command)
   - Path-based exemptions (via settings)
   - View-based exemptions (via decorator)
"""
