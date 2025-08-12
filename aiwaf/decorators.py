from functools import wraps
from django.utils.decorators import method_decorator

def aiwaf_exempt(view_func):
    """
    Decorator to exempt a view from AI-WAF protection.
    Can be used on function-based views or class-based views.
    
    Usage:
        @aiwaf_exempt
        def my_view(request):
            return HttpResponse("This view is exempt from AI-WAF")
        
        # Or for class-based views:
        @method_decorator(aiwaf_exempt, name='dispatch')
        class MyView(View):
            pass
    """
    @wraps(view_func)
    def wrapped_view(*args, **kwargs):
        return view_func(*args, **kwargs)
    
    # Mark the view as AI-WAF exempt
    wrapped_view.aiwaf_exempt = True
    return wrapped_view

# For class-based views
aiwaf_exempt_view = method_decorator(aiwaf_exempt, name='dispatch')
