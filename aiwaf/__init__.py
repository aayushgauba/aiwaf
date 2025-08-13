default_app_config = "aiwaf.apps.AiwafConfig"

__version__ = "0.1.9.0"

# Import main middleware classes for easier access
try:
    from .middleware import (
        IPAndKeywordBlockMiddleware,
        RateLimitMiddleware, 
        AIAnomalyMiddleware,
        HoneypotTimingMiddleware,
        UUIDTamperMiddleware
    )
except ImportError as e:
    # Handle import errors gracefully during package installation
    import sys
    if 'runserver' in sys.argv or 'migrate' in sys.argv or 'shell' in sys.argv:
        print(f"Warning: Could not import middleware classes: {e}")
        print("Tip: Run 'python manage.py aiwaf_diagnose' to troubleshoot")
