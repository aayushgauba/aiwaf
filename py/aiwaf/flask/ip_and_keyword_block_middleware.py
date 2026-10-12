# Flask-adapted IPAndKeywordBlockMiddleware
import re
from flask import request, jsonify
from .utils import get_blacklist_extended_info, get_ip, is_exempt
from .blacklist_manager import BlacklistManager
from .storage import get_keyword_store
from .exemption_decorators import should_apply_middleware
from aiwaf.core.ip_keyword import evaluate_keyword_policy, extract_path_segments, KeywordDecision
from aiwaf.core.native_runtime import function as native_function, csv_function
from aiwaf.core.request_context import extract_query_keys_from_flask_request
from aiwaf.core.sql_injection import SQLInjectionPolicy, inspect_wsgi_request

_DEFAULT_EVALUATE_POLICY = evaluate_keyword_policy

class IPAndKeywordBlockMiddleware:
    def __init__(self, app=None):
        self.app = app
        self.keyword_learning_enabled = True
        self.dynamic_top_n = 10
        self.exempt_keywords = set()
        self.legitimate_path_keywords = set()
        self.safe_prefixes = set()
        self.malicious_keywords = {".php", "xmlrpc", "wp-", ".env", ".git", ".bak", "shell", "filemanager"}
        if app is not None:
            self.keyword_learning_enabled = bool(app.config.get("AIWAF_ENABLE_KEYWORD_LEARNING", True))
            self.dynamic_top_n = int(app.config.get("AIWAF_DYNAMIC_TOP_N", 10))
            self.exempt_keywords = self._get_exempt_keywords(app)
            self.legitimate_path_keywords = self._get_legitimate_path_keywords(app)
            self.safe_prefixes = self._collect_safe_prefixes(app)
            self.init_app(app)

    def _get_exempt_keywords(self, app):
        tokens = set()
        for path in app.config.get("AIWAF_EXEMPT_PATHS", set()) or set():
            for seg in re.split(r"\W+", str(path).strip("/").lower()):
                if len(seg) > 3:
                    tokens.add(seg)
        tokens.update(app.config.get("AIWAF_EXEMPT_KEYWORDS", []) or [])
        return tokens

    def _get_legitimate_path_keywords(self, app):
        default_legitimate = {
            "profile", "user", "users", "account", "accounts", "settings", "dashboard",
            "home", "about", "contact", "help", "search", "list", "lists", "view",
            "views", "edit", "create", "update", "delete", "detail", "details", "api",
            "auth", "login", "logout", "register", "signup", "signin", "reset",
            "confirm", "activate", "verify", "page", "pages", "category", "categories",
            "tag", "tags", "post", "posts", "article", "articles", "blog", "blogs",
            "news", "item", "items", "admin", "administration", "manage", "manager",
            "control", "panel", "config", "configuration", "option", "options",
            "preference", "preferences",
        }
        route_keywords = set()
        for rule in app.url_map.iter_rules():
            for seg in re.findall(r"([a-zA-Z]\w{2,})", str(rule.rule).lower()):
                route_keywords.add(seg)
        route_keywords.update(app.config.get("AIWAF_ALLOWED_PATH_KEYWORDS", []) or [])
        route_keywords.update(app.config.get("AIWAF_EXEMPT_KEYWORDS", []) or [])
        return default_legitimate | route_keywords

    def _collect_safe_prefixes(self, app):
        prefixes = set()
        for rule in app.url_map.iter_rules():
            path = str(rule.rule).strip("/")
            if not path:
                continue
            first = path.split("/")[0]
            if first:
                prefixes.add(first.lower())
        return prefixes

    def init_app(self, app):
        self.sql_policy = SQLInjectionPolicy(app.config.get("AIWAF_SQL_INJECTION_MODE"), app.config.get("AIWAF_PAYLOAD_MAX_BYTES"))
        @app.before_request
        def before_request():
            # Check exemption status first - skip if exempt from this middleware
            if not should_apply_middleware('ip_keyword_block'):
                return None  # Allow request to proceed without IP/keyword checking
            
            # Legacy exemption check for backward compatibility
            if is_exempt(request):
                return None  # Allow request to proceed
            
            ip = get_ip()
            path = request.path.lower()
            path_exists = bool(getattr(request, "endpoint", None))
            
            # Get logger if available
            logger = getattr(app, 'aiwaf_logger', None)
            
            # Check if IP is blacklisted first
            if BlacklistManager.is_blocked(ip):
                if logger:
                    logger.mark_request_blocked(f"IP blacklisted: {ip}")
                return jsonify({"error": "blocked"}), 403
            
            keyword_store = get_keyword_store()
            finding = inspect_wsgi_request(request, self.sql_policy)
            if finding:
                if logger:
                    logger.mark_request_blocked(finding.rule)
                return jsonify({"error": finding.rule}), finding.status
            from .storage import _get_storage_mode, _get_data_dir
            custom_policy = (evaluate_keyword_policy is not _DEFAULT_EVALUATE_POLICY
                or getattr(self._evaluate_keyword_request, '__func__', None) is not self._default_evaluate_request.__func__)
            store_combined = (csv_function('csv_keyword_apply_from_store')
                              if _get_storage_mode() == 'csv' and request.path.isascii() and not custom_policy else None)
            dynamic_top = (keyword_store.get_top_keywords(self.dynamic_top_n)
                           if self.keyword_learning_enabled and store_combined is None else [])

            def _is_malicious_context(seg: str) -> bool:
                query = request.query_string.decode("utf-8", errors="ignore").lower() if request.query_string else ""
                if seg in query and any(token in query for token in ("union", "select", "drop", "insert", "script", "alert", "eval")):
                    return True
                if "../" in path or "..\\" in path:
                    return True
                if seg.startswith(".") and not path_exists:
                    return True
                if (not path_exists) and any(ext in seg for ext in (".php", ".asp", ".jsp", ".cgi")):
                    return True
                return False

            native = native_function('policy_keyword_flask') if not custom_policy else None
            from .storage import _get_storage_mode, _get_data_dir
            combined = csv_function('csv_keyword_apply') if _get_storage_mode() == 'csv' else None
            learned_natively = False
            if native is not None and request.path.isascii():
                args = (
                    request.path, request.query_string.decode('utf-8', errors='ignore'),
                    set(extract_query_keys_from_flask_request(request)), path_exists,
                    self.keyword_learning_enabled, set(self.malicious_keywords), set(dynamic_top),
                    set(self.legitimate_path_keywords), set(self.exempt_keywords),
                    list(self.safe_prefixes), set(self.malicious_keywords))
                if store_combined is not None:
                    from pathlib import Path
                    from aiwaf.core.storage_ops import now_iso
                    from aiwaf.core.storage_schema import KEYWORDS_CSV
                    decision = KeywordDecision(*store_combined(str(Path(_get_data_dir()) / KEYWORDS_CSV),
                        now_iso(), *args[:6], *args[7:], self.dynamic_top_n))
                    learned_natively = True
                elif combined is not None:
                    from pathlib import Path
                    from aiwaf.core.storage_ops import now_iso
                    from aiwaf.core.storage_schema import KEYWORDS_CSV
                    decision = KeywordDecision(*combined(
                        str(Path(_get_data_dir()) / KEYWORDS_CSV), now_iso(), *args))
                    learned_natively = True
                else:
                    decision = KeywordDecision(*native(*args))
            else:
                decision = self._evaluate_keyword_request(request, path_exists, dynamic_top, _is_malicious_context)
            if not learned_natively:
                for seg in decision.learned_keywords:
                    keyword_store.add_keyword(seg)
            if decision.block_reason:
                BlacklistManager.block(
                    ip,
                    decision.block_reason,
                    extended_request_info=get_blacklist_extended_info(request),
                )
                if logger:
                    logger.mark_request_blocked(decision.block_reason)
                return jsonify({"error": "blocked"}), 403

    def _evaluate_keyword_request(self, request, path_exists, dynamic_top, context):
        return evaluate_keyword_policy(
                path=request.path,
                query_keys=list(extract_query_keys_from_flask_request(request)),
                path_exists=path_exists,
                keyword_learning_enabled=self.keyword_learning_enabled,
                static_keywords=self.malicious_keywords,
                dynamic_keywords=dynamic_top,
                legitimate_keywords=set(self.legitimate_path_keywords),
                exempt_keywords=set(self.exempt_keywords),
                safe_prefixes=self.safe_prefixes,
                malicious_keywords=set(self.malicious_keywords),
                is_malicious_context=context,
            )

    _default_evaluate_request = _evaluate_keyword_request
