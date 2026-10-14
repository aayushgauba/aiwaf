"""
AI Anomaly Detection Middleware for Flask

This middleware uses machine learning to detect anomalous behavior patterns
and automatically blocks malicious IPs based on request characteristics.
"""

import re
import time
import logging
import os
from threading import RLock
from datetime import datetime, timezone
from flask import request, jsonify, g, current_app
from .utils import get_ip, is_exempt, is_path_exempt
from .blocklist_manager import BlocklistManager
from .exemption_decorators import should_apply_middleware
from aiwaf.core import rust_backend
from aiwaf.core.anomaly import evaluate_anomaly as core_evaluate_anomaly
from aiwaf.core.anomaly import select_native_history, prune_inactive_histories
from aiwaf.core.logs import write_csv_log
from aiwaf.core.model_security import is_trusted_model_path
from aiwaf.core.model_serialization import load_model_artifact

# Try to import numpy and ML dependencies
try:
    import numpy as np
    NUMPY_AVAILABLE = True
except ImportError:
    NUMPY_AVAILABLE = False
    np = None

# Static malicious keywords (similar to Django implementation)
STATIC_KEYWORDS = {
    'admin', 'wp-admin', 'wp-content', 'wp-includes', 'wp-config', 'xmlrpc',
    'phpmyadmin', 'adminer', 'config', 'configuration', 'settings', 'setup',
    'install', 'installer', 'backup', 'database', 'mysql', 'sql', 'dump',
    '.env', '.git', '.htaccess', '.htpasswd', 'passwd', 'shadow', 'robots',
    'cgi-bin', 'scripts', 'shell', 'cmd', 'exec', 'system', 'eval', 'base64',
    'union', 'select', 'drop', 'delete', 'insert', 'update', 'script', 'javascript',
    'onload', 'onerror', 'onclick', 'document', 'cookie', 'alert'
}

# Status code mapping for ML features
STATUS_CODES = ['200', '201', '204', '301', '302', '400', '401', '403', '404', '405', '500', '502', '503']

class AIAnomalyMiddleware:
    """
    AI-powered anomaly detection middleware for Flask.
    
    Analyzes request patterns and uses machine learning to detect
    and block malicious behavior automatically.
    """
    
    def __init__(self, app=None):
        self.app = app
        self.model = None
        self.model_is_rust = False
        self.malicious_keywords = set(STATIC_KEYWORDS)
        self.request_cache = {}  # Simple in-memory cache for request history
        self._history_lock = RLock()
        self._history_cleanup_at = 0.0
        self.window_seconds = 60
        self.top_n = 10
        
        # Periodic AI check
        self.last_ai_check = 0
        self.ai_check_interval = app.config.get('AIWAF_AI_CHECK_INTERVAL', 3600) if app else 3600  # Default: Check every hour
        
        # Setup logging
        self.logger = logging.getLogger(__name__)
        
        if app is not None:
            self.init_app(app)

    def init_app(self, app):
        """Initialize the middleware with Flask app."""
        self.app = app
        
        # Configuration
        self.window_seconds = app.config.get('AIWAF_WINDOW_SECONDS', 60)
        self.top_n = app.config.get('AIWAF_DYNAMIC_TOP_N', 10)
        
        # Try to load ML model
        self._load_model(app)
        
        # Register middleware hooks
        app.before_request(self.before_request)
        app.after_request(self.after_request)

    def _get_default_model_path(self):
        """Get the default model path relative to the package."""
        from pathlib import Path
        
        # Get the directory where this file is located
        middleware_dir = Path(__file__).parent
        resources_dir = middleware_dir / 'resources'
        
        # Ensure resources directory exists
        resources_dir.mkdir(exist_ok=True)
        
        return str(resources_dir / 'model.json')

    def _check_log_data_sufficiency(self, app):
        """Check if there's enough log data to justify AI model usage."""
        min_ai_threshold = app.config.get('AIWAF_MIN_AI_LOGS', 10000)
        log_dir = app.config.get('AIWAF_LOG_DIR', 'logs')
        
        total_lines = 0
        try:
            import os
            import glob
            
            # Count lines in all log files
            log_patterns = [
                os.path.join(log_dir, '*.log'),
                os.path.join(log_dir, '*.csv'),
                os.path.join(log_dir, '*.json'),
                os.path.join(log_dir, '*.jsonl'),
            ]
            
            for pattern in log_patterns:
                for log_file in glob.glob(pattern):
                    try:
                        with open(log_file, 'r', encoding='utf-8', errors='ignore') as f:
                            total_lines += sum(1 for _ in f)
                    except Exception as e:
                        self.logger.debug(f"Error reading {log_file}: {e}")
                        continue
            
            self.logger.info(f"Found {total_lines} total log lines, threshold: {min_ai_threshold}")
            return total_lines >= min_ai_threshold
            
        except Exception as e:
            self.logger.warning(f"Could not check log data sufficiency: {e}")
            return True  # Default to allowing AI if we can't check

    def _check_ai_status_periodically(self, app):
        """Periodically re-evaluate whether AI should be enabled based on current log data."""
        import time
        
        current_time = time.time()
        
        # Only check periodically to avoid performance impact
        if current_time - self.last_ai_check < self.ai_check_interval:
            return
            
        self.last_ai_check = current_time
        
        # Re-evaluate log data sufficiency
        force_ai = app.config.get('AIWAF_FORCE_AI', False)
        
        if force_ai:
            # If forcing AI, ensure model is loaded if available
            if self.model is None:
                self.logger.info("Force AI enabled - attempting to reload model")
                self._load_model(app)
            return
        
        # Check current log data sufficiency
        has_sufficient_data = self._check_log_data_sufficiency(app)
        
        if has_sufficient_data and self.model is None:
            # We now have enough data but no model - try to load it
            self.logger.info("Sufficient log data detected - attempting to load AI model")
            self._load_model(app)
        elif not has_sufficient_data and self.model is not None:
            # We no longer have enough data - disable AI
            self.logger.info("Insufficient log data detected - disabling AI model")
            self.model = None

    def _load_model(self, app):
        """Load the machine learning model if available and sufficient data exists."""
        self.model = None
        self.model_is_rust = False

        def _assign_model(model_data, source_label):
            if isinstance(model_data, dict):
                if model_data.get("model_type") == "aiwaf_rust.IsolationForest":
                    rust_model = rust_backend.rust_isolation_forest_from_json(
                        model_data.get("model_state")
                    )
                    if rust_model is not None:
                        self.model = rust_model
                        self.model_is_rust = True
                        self.logger.info(f"Loaded AI model from {model_path} (aiwaf-rust, {source_label})")
                        return True
                if 'model' in model_data:
                    self.model = model_data['model']
                    self.logger.info(f"Loaded AI model from {model_path} (with metadata, {source_label})")
                    return True
            self.model = model_data
            self.logger.info(f"Loaded AI model from {model_path} (legacy format, {source_label})")
            return True
        # Check if we have enough log data for AI to be effective (unless forced)
        force_ai = app.config.get('AIWAF_FORCE_AI', False)
        if not force_ai and not self._check_log_data_sufficiency(app):
            self.logger.info("Insufficient log data for AI anomaly detection - using keyword-only mode")
            self.logger.info("Use AIWAF_FORCE_AI=True to override this behavior")
            self.model = None
            return
        elif force_ai:
            self.logger.info("AI model loading forced despite potentially insufficient log data")
        
        # Get model path - use package-relative path by default
        default_model_path = self._get_default_model_path()
        model_path = app.config.get('AIWAF_MODEL_PATH', default_model_path)
        allow_custom_model_path = bool(app.config.get('AIWAF_ALLOW_CUSTOM_MODEL_PATH', False))

        if not is_trusted_model_path(model_path, default_path=default_model_path, allow_custom=allow_custom_model_path):
            self.logger.warning(
                "Skipping untrusted AI model path %s; set AIWAF_ALLOW_CUSTOM_MODEL_PATH=True to override",
                model_path,
            )
            self.model = None
            self.model_is_rust = False
            return
        
        try:
            import os
            import warnings
            if os.path.exists(model_path):
                with warnings.catch_warnings():
                    warnings.filterwarnings("ignore", category=UserWarning, module="sklearn")
                    model_data = load_model_artifact(model_path)
                    _assign_model(model_data, "safe artifact")
            else:
                self.logger.warning(f"AI model not found at {model_path}")
        except Exception as e:
            self.logger.error(f"Failed to load AI model: {e}")
            self.logger.info("AI anomaly detection will continue without ML model (keyword-based only)")
            self.model = None
            self.model_is_rust = False

        if self.model is not None and not self.model_is_rust and not NUMPY_AVAILABLE:
            self.logger.warning("NumPy not available - disabling sklearn-based AI model")
            self.model = None
            self.model_is_rust = False

    def _is_malicious_context(self, request_obj, keyword):
        """
        Determine if a keyword appears in a malicious context.
        Only learn keywords when we have strong indicators of malicious intent.
        """
        path = request_obj.path.lower()
        query_string = request_obj.query_string.decode('utf-8', errors='ignore').lower()
        
        # Strong malicious indicators
        malicious_indicators = [
            # Multiple consecutive suspicious segments
            len([seg for seg in re.split(r"\W+", path) if seg in self.malicious_keywords]) > 1,
            
            # Common attack patterns in path
            any(pattern in path for pattern in [
                '../', '..\\', '.env', 'wp-admin', 'phpmyadmin', 'config',
                'backup', 'database', 'mysql', 'passwd', 'shadow', 'admin',
                'shell', 'cmd', 'exec', 'system'
            ]),
            
            # Suspicious query parameters
            any(param in request_obj.args for param in ['cmd', 'exec', 'system', 'shell', 'eval']),
            
            # Multiple directory traversal attempts
            path.count('../') > 2 or path.count('..\\') > 2,
            
            # Encoded attack patterns
            any(encoded in path for encoded in ['%2e%2e', '%252e', '%c0%ae', '%2f', '%5c']),
            
            # SQL injection patterns
            any(sql_pattern in query_string for sql_pattern in [
                'union select', 'drop table', 'insert into', 'delete from', 'update set'
            ]),
            
            # XSS patterns
            any(xss_pattern in query_string for xss_pattern in [
                '<script', 'javascript:', 'onload=', 'onerror=', 'document.cookie'
            ])
        ]
        
        return any(malicious_indicators)

    def _route_exists(self, path):
        """
        Check if a route exists in the Flask application.
        This is the Flask equivalent of Django's path_exists_in_django.
        """
        try:
            from flask import current_app
            from werkzeug.routing import RequestRedirect
            from werkzeug.exceptions import MethodNotAllowed
            
            # Test if the path matches any route
            route_map = current_app.url_map
            cached = getattr(g, '_aiwaf_anomaly_route_adapter', None)
            if cached is None or cached[0] is not route_map:
                cached = (route_map, route_map.bind('localhost'))
                g._aiwaf_anomaly_route_adapter = cached
            adapter = cached[1]
            try:
                adapter.match(path)
                return True
            except (RequestRedirect, MethodNotAllowed):
                # Route exists but wrong method or redirect
                return True
            except:
                # No route found
                return False
        except:
            return False

    def _calculate_features(self, request_obj, ip, response_time=0):
        """Calculate ML features for the current request."""
        path = request_obj.path
        path_len = len(path)
        
        # Check if route exists
        known_path = self._route_exists(path)
        
        # Count keyword hits
        kw_hits = 0
        if not known_path and not is_path_exempt(path):
            kw_hits = sum(1 for kw in self.malicious_keywords if kw in path.lower())
        
        # Get request history for this IP
        now = time.time()
        key = f"aiwaf:{ip}"
        data = self.request_cache.get(key, [])
        
        # Calculate burst count (requests within last 10 seconds)
        burst_count = sum(1 for (t, _, _, _) in data if now - t <= 10)
        
        # Calculate total 404s
        total_404 = sum(1 for (_, _, st, _) in data if st == 404)
        
        # Status code index (default to -1 for unknown)
        status_idx = -1  # Will be set when we know the response status
        
        return [path_len, kw_hits, response_time, status_idx, burst_count, total_404]

    def before_request(self):
        """Process request before it reaches the route handler."""
        # Check exemption status first - skip if exempt from AI anomaly detection
        if not should_apply_middleware('ai_anomaly'):
            return None  # Allow request to proceed without AI anomaly checking
        
        # Periodically check if AI should be enabled/disabled
        self._check_ai_status_periodically(current_app)
        
        # Legacy exemption check for backward compatibility
        if is_exempt(request):
            return None
            
        # Record start time for response time calculation
        g.aiwaf_start_time = time.time()
        
        # Get client IP
        ip = get_ip()
        
        # Check if IP is already blocked
        if BlocklistManager.is_blocked(ip):
            return jsonify({"error": "blocked"}), 403
            
        return None

    def after_request(self, response):
        """Process response after request completion."""
        # Check if request should be exempt
        if is_exempt(request):
            return response
            
        ip = get_ip()
        now = time.time()
        
        # Calculate response time
        start_time = getattr(g, 'aiwaf_start_time', now)
        resp_time = now - start_time
        
        key = f"aiwaf:{ip}"
        with self._history_lock:
            if now >= self._history_cleanup_at or now < self._history_cleanup_at - 30.0:
                prune_inactive_histories(self.request_cache, now=now, window_seconds=self.window_seconds)
                self._history_cleanup_at = now + 30.0
            data = self.request_cache.get(key, [])

        outcome = core_evaluate_anomaly(
            ip=ip,
            path=request.path,
            status_code=int(getattr(response, "status_code", 0) or 0),
            response_time=float(resp_time),
            now=float(now),
            history=select_native_history(data, self.model,
                enabled=bool(current_app.config.get('AIWAF_RUST_ANOMALY_HISTORY', True))),
            window_seconds=float(self.window_seconds),
            model=self.model,
            static_keywords=list(STATIC_KEYWORDS),
            malicious_keywords=list(self.malicious_keywords),
            keyword_learning_enabled=True,
            path_exists=self._route_exists,
            is_exempt_path=is_path_exempt,
            is_malicious_context=lambda seg: self._is_malicious_context(request, seg),
            status_index_values=STATUS_CODES,
            legitimate_keywords=set(),
        )

        with self._history_lock:
            self.request_cache[key] = outcome.updated_history

        if outcome.learned_keywords:
            try:
                from .storage import get_keyword_store
                keyword_store = get_keyword_store()
                for seg in outcome.learned_keywords:
                    keyword_store.add_keyword(seg)
                    self.malicious_keywords.add(seg)
                    self.logger.info(f"Learned new malicious keyword: {seg}")
            except Exception as e:
                self.logger.error(f"Error learning keywords: {e}")

        if outcome.block and outcome.reason:
            BlocklistManager.block(ip, outcome.reason)
            self.logger.warning(f"Blocked IP {ip}: {outcome.reason}")
            if BlocklistManager.is_blocked(ip):
                return jsonify({"error": "blocked"}), 403

        self._persist_training_log(ip, response, resp_time)
        return response

    def _persist_training_log(self, ip, response, response_time):
        """Persist fallback training logs when dedicated logger middleware is inactive."""
        if self.app.config.get("AIWAF_MIDDLEWARE_LOGGING", False):
            return
        if self.app.config.get("AIWAF_ACCESS_LOG"):
            return

        log_dir = self.app.config.get("AIWAF_LOG_DIR", "logs")
        csv_file = os.path.join(log_dir, "aiwaf_requests.csv")
        headers = [
            "timestamp",
            "ip",
            "method",
            "path",
            "status_code",
            "content_length",
            "response_time_ms",
            "referer",
            "user_agent",
        ]
        row = {
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "ip": ip,
            "method": request.method,
            "path": request.path[:500],
            "status_code": int(getattr(response, "status_code", 0) or 0),
            "content_length": response.headers.get("Content-Length", "-"),
            "response_time_ms": int(float(response_time) * 1000),
            "referer": request.headers.get("Referer", "")[:500],
            "user_agent": request.headers.get("User-Agent", "")[:2000],
        }
        try:
            write_csv_log(csv_file, headers, row,
                durable=bool(self.app.config.get('AIWAF_CSV_LOG_FSYNC', False)))
        except Exception:
            pass

    def get_stats(self):
        """Get statistics about the anomaly detection middleware."""
        return {
            'model_loaded': self.model is not None,
            'numpy_available': NUMPY_AVAILABLE,
            'json_model_artifacts': True,
            'cached_ips': len(self.request_cache),
            'malicious_keywords': len(self.malicious_keywords),
            'window_seconds': self.window_seconds
        }


# Compatibility aliases for callers using the previous terminology.
BlacklistManager = BlocklistManager
