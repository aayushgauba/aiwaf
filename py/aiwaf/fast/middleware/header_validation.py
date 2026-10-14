"""
Header validation middleware for FastAPI - detects bots and malicious requests.
"""
import re
import logging
from typing import Callable, List, Dict, Any, Set, Optional
from fastapi import Request, Response
from fastapi.responses import JSONResponse
from starlette.middleware.base import BaseHTTPMiddleware

from ..utils import get_blocklist_extended_info, get_ip, is_exempt, is_static_file
from ..blocklist import BlocklistManager
from ..decorators import should_apply_middleware
from aiwaf.core import header_validation as core_header_validation
from aiwaf.core.rust_backend import validate_headers as rust_validate_headers, rust_available
from aiwaf.core.request_context import normalized_headers_to_wsgi_environ

logger = logging.getLogger(__name__)


class HeaderValidationMiddleware(BaseHTTPMiddleware):
    """
    FastAPI middleware that validates HTTP headers to detect bots and malicious requests.
    
    This middleware analyzes request headers to identify:
    - Missing required browser headers
    - Suspicious user agent patterns
    - Unusual header combinations
    - Low-quality header profiles
    """
    
    # Standard browser headers that legitimate requests should have
    REQUIRED_HEADERS = [
        h.replace('HTTP_', '').replace('_', '-').lower()
        for h in core_header_validation.REQUIRED_HEADERS
    ]
    
    # Headers that browsers typically send
    BROWSER_HEADERS = [
        h.replace('HTTP_', '').replace('_', '-').lower()
        for h in core_header_validation.BROWSER_HEADERS
    ]
    
    # Suspicious User-Agent patterns
    SUSPICIOUS_USER_AGENTS = list(core_header_validation.SUSPICIOUS_USER_AGENTS) + [r'mozilla/5\.0$']
    
    # Known legitimate bot user agents to allowlist
    LEGITIMATE_BOTS = list(core_header_validation.LEGITIMATE_BOTS)
    
    def __init__(
        self,
        app,
        enabled: bool = True,
        block_suspicious: bool = True,
        quality_threshold: int = 3,
        exempt_paths: Optional[Set[str]] = None,
        custom_suspicious_patterns: Optional[List[str]] = None,
        custom_legitimate_patterns: Optional[List[str]] = None,
        trust_legitimate_bots: bool = False,
        path_rules: Optional[List[Dict[str, Any]]] = None,
    ):
        """
        Initialize the header validation middleware.
        
        Args:
            app: FastAPI application
            enabled: Whether the middleware is enabled
            block_suspicious: Whether to block suspicious requests
            quality_threshold: Minimum header quality score required
            exempt_paths: Additional paths to exempt from validation
            custom_suspicious_patterns: Additional suspicious UA patterns
            custom_legitimate_patterns: Additional legitimate bot patterns
            trust_legitimate_bots: Allow listed bot user agents to bypass suspicion checks
        """
        super().__init__(app)
        self.enabled = enabled
        self.block_suspicious = block_suspicious
        self.quality_threshold = quality_threshold
        self.exempt_paths = exempt_paths or set()
        self.trust_legitimate_bots = trust_legitimate_bots
        self.path_rules = path_rules or []
        
        # Extend patterns with custom ones
        if custom_suspicious_patterns:
            self.suspicious_patterns = self.SUSPICIOUS_USER_AGENTS + custom_suspicious_patterns
        else:
            self.suspicious_patterns = self.SUSPICIOUS_USER_AGENTS
            
        if custom_legitimate_patterns:
            self.legitimate_patterns = self.LEGITIMATE_BOTS + custom_legitimate_patterns
        else:
            self.legitimate_patterns = self.LEGITIMATE_BOTS
        
        self.suspicious_combinations = list(core_header_validation.SUSPICIOUS_COMBINATIONS)
    
    async def dispatch(self, request: Request, call_next: Callable) -> Response:
        """Process the request through header validation."""
        logger.debug(f"HeaderValidationMiddleware: Processing request to {request.url.path}")
        
        if not self.enabled:
            logger.debug("HeaderValidationMiddleware: Disabled, skipping")
            return await call_next(request)

        if not should_apply_middleware(request, "header_validation", self.path_rules):
            return await call_next(request)
        
        # Skip if request is exempted
        if is_exempt(request, self.exempt_paths):
            logger.debug(f"HeaderValidationMiddleware: Path {request.url.path} is exempted")
            return await call_next(request)
        
        ip = get_ip(request)
        logger.debug(f"HeaderValidationMiddleware: Processing IP {ip}")
        
        # Check IP-level exemption
        from ..storage import get_exemption_store
        exemption_store = get_exemption_store()
        if exemption_store.is_exempted(ip):
            return await call_next(request)
        
        # Skip for static files and common paths
        if self._is_static_request(request):
            return await call_next(request)
        
        # Normalize header keys for deterministic lookups in middleware checks.
        # Prefer ASGI scope headers (already lowercased by spec), then overlay with
        # request.headers to remain robust across server/test-client variations.
        headers = {}
        for key, value in request.scope.get("headers", []):
            try:
                headers[key.decode("latin-1").lower()] = value.decode("latin-1")
            except Exception:
                continue
        headers.update({k.lower(): v for k, v in request.headers.items()})
        
        try:
            quality_score = self._calculate_header_quality(headers)
            violation_reason = None
            environ = self._to_core_environ(headers, request.scope)

            # Keep optional Rust fast-path, then apply core Python evaluator for parity.
            if rust_available():
                violation_reason = rust_validate_headers(
                    headers,
                    required_headers=self.REQUIRED_HEADERS,
                    min_score=self.quality_threshold,
                )
            if (
                violation_reason
                and "Empty user agent" in violation_reason
                and self._get_header(request, "user-agent")
            ):
                violation_reason = None

            if violation_reason is None:
                required_headers_env = [f"HTTP_{h.upper().replace('-', '_')}" for h in self.REQUIRED_HEADERS]
                violation_reason = core_header_validation.evaluate_header_policy(
                    environ,
                    method=request.method,
                    config_required_headers={request.method.upper(): required_headers_env},
                    min_score=self.quality_threshold,
                    suspicious_user_agents=self.suspicious_patterns,
                    legitimate_bots=self.legitimate_patterns,
                    suspicious_combinations=self.suspicious_combinations,
                    browser_headers=[f"HTTP_{h.upper().replace('-', '_')}" for h in self.BROWSER_HEADERS],
                )

            if violation_reason:
                if not self.block_suspicious:
                    logger.warning(
                        f"Header validation would block {ip}: {violation_reason} "
                        f"(Path: {request.url.path})"
                    )
                    return await call_next(request)
                
                return self._block_request(ip, violation_reason, request.url.path, request=request)
            
            # Log legitimate request (debug level)
            logger.debug(
                f"Header validation passed for {ip} - "
                f"Path: {request.url.path}, Quality: {quality_score}"
            )
            
        except Exception as e:
            logger.error(f"Error in header validation for {ip}: {e}")
            # Don't block on validation errors, just log and continue
        
        return await call_next(request)
    
    def _is_static_request(self, request: Request) -> bool:
        """Check if this is a request for static files"""
        path = request.url.path.lower()
        
        # Use the utility function
        if is_static_file(path):
            return True
        
        # Check additional static paths
        static_paths = ['/static/', '/media/', '/assets/', '/favicon.ico']
        if any(path.startswith(static_path) for static_path in static_paths):
            return True
        
        return False
    
    def _check_missing_headers(self, headers: Dict[str, str]) -> List[str]:
        """Check for missing required headers"""
        missing = []
        
        for header in self.REQUIRED_HEADERS:
            if not headers.get(header):
                missing.append(header)
        
        return missing

    def _get_header(self, request: Request, name: str) -> Optional[str]:
        """Get header value from request with robust ASGI/raw fallback."""
        value = request.headers.get(name)
        if value:
            return value

        name_lower = name.lower().encode("latin-1")
        for key, raw_value in request.scope.get("headers", []):
            try:
                if key.lower() == name_lower:
                    decoded = raw_value.decode("latin-1")
                    if decoded:
                        return decoded
            except Exception:
                continue
        return None
    
    def _check_user_agent(self, user_agent: str) -> Optional[str]:
        """Check if user agent is suspicious"""
        if not user_agent:
            # Missing UA is handled by required-header checks when enabled.
            return None
        
        user_agent_lower = user_agent.lower()
        
        is_legitimate_bot = any(
            re.search(legitimate_pattern, user_agent_lower)
            for legitimate_pattern in self.legitimate_patterns
        )
        
        # Check for suspicious patterns
        suspicious_match = None
        for suspicious_pattern in self.suspicious_patterns:
            if re.search(suspicious_pattern, user_agent_lower, re.IGNORECASE):
                suspicious_match = suspicious_pattern
                break
        
        if suspicious_match:
            if self.trust_legitimate_bots and is_legitimate_bot:
                logger.debug(
                    "User agent matched legitimate bot pattern; skipping suspicion block"
                )
            else:
                return f"Pattern: {suspicious_match}"
        
        if is_legitimate_bot:
            return None
        
        # Check for very short user agents (likely fake)
        if len(user_agent) < 10:
            return "Too short"
        
        # Check for very long user agents (possibly malicious)
        if len(user_agent) > 500:
            return "Too long"
        
        return None
    
    def _check_header_combinations(self, headers: Dict[str, str], scope: Dict[str, Any]) -> Optional[str]:
        """Check suspicious header combinations using shared core logic."""
        environ = self._to_core_environ(headers, scope)
        required = [f"HTTP_{h.upper().replace('-', '_')}" for h in self.REQUIRED_HEADERS]
        return core_header_validation._check_header_combinations(environ, required)
    
    def _calculate_header_quality(self, headers: Dict[str, str]) -> int:
        """Calculate a quality score based on shared core logic."""
        return core_header_validation._calculate_header_quality(self._to_core_environ(headers, {}))

    def _to_core_environ(self, headers: Dict[str, str], scope: Dict[str, Any]) -> Dict[str, str]:
        """Map ASGI headers/scope into core validator environ format."""
        return normalized_headers_to_wsgi_environ(headers, scope.get("http_version", ""))
    
    def _block_request(self, ip: str, reason: str, path: str, request: Optional[Request] = None) -> Response:
        """Block the request and return error response"""
        if not self.block_suspicious:
            logger.warning(f"Would block {ip}: {reason} (Path: {path})")
            return JSONResponse(
                content={
                    "warning": "suspicious_headers", 
                    "message": "Request has suspicious headers but blocking is disabled",
                    "path": path
                },
                status_code=200  # Don't actually block
            )
        
        from ..storage import get_exemption_store
        exemption_store = get_exemption_store()
        
        # Double-check exemption before blocking
        if not exemption_store.is_exempted(ip):
            extended_info = get_blocklist_extended_info(request) if request is not None else None
            BlocklistManager.block(
                ip,
                f"Header validation: {reason}",
                extended_request_info=extended_info,
            )
            
            # Check if actually blocked (exempted IPs won't be blocked)
            if BlocklistManager.is_blocked(ip):
                logger.warning(f"Blocked {ip}: {reason} (Path: {path})")
                return JSONResponse(
                    content={
                        "error": "blocked",
                        "message": "Request blocked due to suspicious headers",
                        "path": path
                    },
                    status_code=403
                )
        
        # If we get here, IP was exempted after the fact
        logger.info(f"IP {ip} exempted, not blocking: {reason}")
        return JSONResponse(
            content={
                "info": "exempted",
                "message": "Request flagged but IP is exempted",
                "path": path
            },
            status_code=200
        )
    
    def get_statistics(self) -> Dict[str, Any]:
        """Get middleware statistics"""
        return {
            'enabled': self.enabled,
            'block_suspicious': self.block_suspicious,
            'quality_threshold': self.quality_threshold,
            'rust_backend_enabled': rust_available(),
            'suspicious_pattern_count': len(self.suspicious_patterns),
            'legitimate_pattern_count': len(self.legitimate_patterns),
            'combination_check_count': len(self.suspicious_combinations)
        }
    
    def add_suspicious_pattern(self, pattern: str):
        """Add a custom suspicious user agent pattern"""
        if pattern not in self.suspicious_patterns:
            self.suspicious_patterns.append(pattern)
            logger.info(f"Added suspicious pattern: {pattern}")
    
    def add_legitimate_pattern(self, pattern: str):
        """Add a custom legitimate bot pattern"""
        if pattern not in self.legitimate_patterns:
            self.legitimate_patterns.append(pattern)
            logger.info(f"Added legitimate pattern: {pattern}")
    
    def remove_suspicious_pattern(self, pattern: str):
        """Remove a suspicious user agent pattern"""
        if pattern in self.suspicious_patterns:
            self.suspicious_patterns.remove(pattern)
            logger.info(f"Removed suspicious pattern: {pattern}")
    
    def remove_legitimate_pattern(self, pattern: str):
        """Remove a legitimate bot pattern"""
        if pattern in self.legitimate_patterns:
            self.legitimate_patterns.remove(pattern)
            logger.info(f"Removed legitimate pattern: {pattern}")
    
    def enable(self):
        """Enable the middleware"""
        self.enabled = True
        logger.info("Header validation middleware enabled")
    
    def disable(self):
        """Disable the middleware"""
        self.enabled = False
        logger.info("Header validation middleware disabled")
    
    def set_quality_threshold(self, threshold: int):
        """Set the header quality threshold"""
        self.quality_threshold = threshold
        logger.info(f"Header quality threshold set to {threshold}")
    
    def enable_blocking(self):
        """Enable blocking of suspicious requests"""
        self.block_suspicious = True
        logger.info("Header validation blocking enabled")
    
    def disable_blocking(self):
        """Disable blocking of suspicious requests (warning mode)"""
        self.block_suspicious = False
        logger.info("Header validation blocking disabled (warning mode)")


# Compatibility aliases for callers using the previous terminology.
get_blacklist_extended_info = get_blocklist_extended_info
BlacklistManager = BlocklistManager
