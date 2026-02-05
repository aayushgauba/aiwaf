# AIWAF Configuration Example
# Add these settings to your Django settings.py to configure AIWAF

# =============================================================================
# AIWAF KEYWORD PROTECTION SETTINGS
# =============================================================================

# Explicitly allowed path keywords (won't be blocked in legitimate paths)
# These keywords are safe when they appear in valid Django URL paths
AIWAF_ALLOWED_PATH_KEYWORDS = [
    # Common legitimate path segments
    "profile", "user", "account", "settings", "dashboard",
    "admin", "api", "auth", "login", "logout", "register",
    "search", "list", "detail", "edit", "create", "update",
    "delete", "view", "page", "category", "tag", "post",
    "article", "blog", "news", "contact", "about", "help",
    
    # Site-specific legitimate keywords (customize for your site)
    "buddycraft", "sc2", "starcraft", "replay", "match",
    "game", "player", "tournament", "ladder", "clan",
    "team", "guild", "league", "season", "rank",
    
    # Add your own site-specific keywords here
    # "myapp", "feature", "service", etc.
]

# Keywords that should NEVER trigger blocking (highest priority)
AIWAF_EXEMPT_KEYWORDS = [
    "api", "webhook", "health", "static", "media",
    "upload", "download", "backup", "profile", "admin"
]

# =============================================================================
# EXISTING AIWAF SETTINGS (configure as needed)
# =============================================================================

# Paths that are completely exempt from AIWAF protection
AIWAF_EXEMPT_PATHS = [
    "/api/webhook/",       # API endpoints
    "/health-check/",      # Monitoring
    "/static/",            # Static files
    "/media/",             # Media files
    "/admin/jsi18n/",      # Django admin i18n
]

# Static malicious keywords (always blocked regardless of context)
AIWAF_MALICIOUS_KEYWORDS = [
    ".php", "xmlrpc", "wp-", ".env", ".git", ".bak",
    "config", "shell", "filemanager", "phpmyadmin",
    "administrator", "manager", "eval", "system"
]

# =============================================================================
# AIWAF BEHAVIOR SETTINGS
# =============================================================================

# Number of top dynamic keywords to consider for blocking
AIWAF_DYNAMIC_TOP_N = 5  # Reduced from 10 for more conservative blocking

# Rate limiting settings
AIWAF_RATE_WINDOW = 10     # seconds
AIWAF_RATE_MAX = 20        # soft limit (warnings)
AIWAF_RATE_FLOOD = 40      # hard limit (immediate block)

# Header validation overrides (optional)
# Per-method example for email scanners that issue HEAD requests.
AIWAF_REQUIRED_HEADERS = {
    "GET": ["HTTP_USER_AGENT", "HTTP_ACCEPT"],
    "HEAD": [],
}
AIWAF_HEADER_QUALITY_MIN_SCORE = 3

# Blacklist extended request info (optional)
AIWAF_BLACKLIST_STORE_EXTENDED_INFO = False
AIWAF_BLACKLIST_REDACT_HEADERS = ["Authorization", "Cookie", "Set-Cookie"]
AIWAF_BLACKLIST_MAX_HEADERS = 50
AIWAF_BLACKLIST_MAX_HEADER_VALUE_LENGTH = 512

# Honeypot timing threshold
AIWAF_MIN_FORM_TIME = 1.0  # minimum seconds for form submission

# AI anomaly detection window
AIWAF_WINDOW_SECONDS = 60  # seconds to analyze behavior

# Model path for AI detection
AIWAF_MODEL_PATH = os.path.join(BASE_DIR, "aiwaf", "resources", "model.pkl")

# Model storage configuration
AIWAF_MODEL_STORAGE = "file"  # file | db | cache
AIWAF_MODEL_CACHE_KEY = "aiwaf:model"
AIWAF_MODEL_CACHE_TIMEOUT = None
AIWAF_MODEL_STORAGE_FALLBACK = True

# Geo-blocking (optional, requires aiwaf[geoblock])
AIWAF_GEO_BLOCK_ENABLED = False
AIWAF_GEOIP_DB_PATH = "aiwaf/geolock/ipinfo_lite.mmdb"
AIWAF_GEO_BLOCK_COUNTRIES = ["CN", "RU"]
AIWAF_GEO_ALLOW_COUNTRIES = []
AIWAF_GEO_CACHE_SECONDS = 3600
AIWAF_GEO_CACHE_PREFIX = "aiwaf:geo:"

# Minimum log thresholds for training
AIWAF_MIN_AI_LOGS = 10000      # minimum log lines for AI training
AIWAF_MIN_TRAIN_LOGS = 50      # minimum log lines for keyword training
AIWAF_FORCE_AI_TRAINING = False  # override AIWAF_MIN_AI_LOGS gate

# =============================================================================
# RECOMMENDED SETTINGS FOR PRODUCTION
# =============================================================================

# For high-traffic sites, be more conservative:
# AIWAF_DYNAMIC_TOP_N = 3
# AIWAF_RATE_MAX = 50
# AIWAF_RATE_FLOOD = 100

# For development/testing, be more lenient:
# AIWAF_DYNAMIC_TOP_N = 10
# AIWAF_RATE_MAX = 100
# AIWAF_RATE_FLOOD = 200

# =============================================================================
# TROUBLESHOOTING
# =============================================================================

# If legitimate requests are being blocked:
# 1. Add the blocked keyword to AIWAF_ALLOWED_PATH_KEYWORDS
# 2. Add the path pattern to AIWAF_EXEMPT_PATHS
# 3. Reduce AIWAF_DYNAMIC_TOP_N to be more conservative
# 4. Clear the blacklist: python manage.py aiwaf_reset --blacklist --confirm

# If attacks are not being detected:
# 1. Increase AIWAF_DYNAMIC_TOP_N
# 2. Review and update AIWAF_MALICIOUS_KEYWORDS
# 3. Retrain the AI model: python manage.py detect_and_train
# 4. Check logs: python manage.py aiwaf_logging --recent
