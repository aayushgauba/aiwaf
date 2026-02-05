# AIWAF Settings Guide
# Add these settings to your Django settings.py file

# =============================================================================
# AIWAF AI Configuration
# =============================================================================

# Legacy nested configuration (optional)
# AIWAF_SETTINGS will be mapped into AIWAF_* values at startup.
# Example keys supported: RATE_LIMITING, EXEMPTIONS, IP_BLOCKING, KEYWORD_DETECTION, LOGGING.
# AIWAF_SETTINGS = {}

# Disable AI functionality globally (optional)
# When set to True, all AI anomaly detection and training will be disabled
# Keyword learning and basic protection will still work
AIWAF_DISABLE_AI = False  # Set to True to disable AI features

# Minimum log thresholds for training
# AI model training only runs when enough log lines are available
AIWAF_MIN_AI_LOGS = 10000       # Minimum logs required for AI model training
AIWAF_MIN_TRAIN_LOGS = 50       # Minimum logs required for keyword learning
AIWAF_FORCE_AI_TRAINING = False # Override AIWAF_MIN_AI_LOGS gate

# Model storage configuration
# Use "db" to store model in the database, or "cache" for cache backends.
AIWAF_MODEL_STORAGE = "file"    # file | db | cache
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

# =============================================================================
# AIWAF Core Settings
# =============================================================================

# Logging configuration
AIWAF_LOGGING_ENABLED = True
AIWAF_LOG_LEVEL = 'INFO'
AIWAF_LOG_FILE = 'aiwaf.log'

# Protection settings
AIWAF_ENABLE_KEYWORD_LEARNING = True
AIWAF_ENABLE_IP_BLOCKING = True
AIWAF_ENABLE_ANOMALY_DETECTION = True  # Ignored if AIWAF_DISABLE_AI is True

# Header validation overrides (optional)
# Can be a list (all methods) or a dict per HTTP method.
# Example: AIWAF_REQUIRED_HEADERS = {"GET": ["HTTP_USER_AGENT", "HTTP_ACCEPT"], "HEAD": []}
AIWAF_REQUIRED_HEADERS = None
# Minimum header quality score (0 disables score blocking when required headers are empty).
AIWAF_HEADER_QUALITY_MIN_SCORE = 3

# Blacklist extended request info (optional)
# Stores URL + headers alongside blacklist entries for later analysis.
AIWAF_BLACKLIST_STORE_EXTENDED_INFO = False
# Redact sensitive headers before storing.
AIWAF_BLACKLIST_REDACT_HEADERS = ["Authorization", "Cookie", "Set-Cookie"]
# Limit the number and size of stored headers to avoid bloating the DB.
AIWAF_BLACKLIST_MAX_HEADERS = 50
AIWAF_BLACKLIST_MAX_HEADER_VALUE_LENGTH = 512

# Learning thresholds
AIWAF_KEYWORD_THRESHOLD = 3
AIWAF_ANOMALY_THRESHOLD = -0.5

# Rate limiting settings
AIWAF_RATE_WINDOW = 10        # Time window in seconds
AIWAF_RATE_MAX = 20           # Soft limit (returns 429 Too Many Requests)
AIWAF_RATE_FLOOD = 40         # Hard limit (blocks IP and returns 403)

# =============================================================================
# Example Django Middleware Configuration
# =============================================================================

# Add AIWAF middleware to your MIDDLEWARE setting:
MIDDLEWARE = [
    'django.middleware.security.SecurityMiddleware',
    'django.contrib.sessions.middleware.SessionMiddleware',
    'django.middleware.common.CommonMiddleware',
    'django.middleware.csrf.CsrfViewMiddleware',
    
    # AIWAF Middleware (add these)
    'aiwaf.middleware.RateLimitMiddleware',           # Rate limiting & burst protection
    'aiwaf.middleware.IPAndKeywordBlockMiddleware',    # Basic protection
    'aiwaf.middleware.AIAnomalyMiddleware',            # AI anomaly detection
    'aiwaf.middleware.KeywordLearningMiddleware',      # Learning middleware
    
    'django.contrib.auth.middleware.AuthenticationMiddleware',
    'django.contrib.messages.middleware.MessageMiddleware',
    'django.middleware.clickjacking.XFrameOptionsMiddleware',
]

# =============================================================================
# Database Configuration (Optional)
# =============================================================================

# If you want to use database storage instead of JSON files,
# make sure to include 'aiwaf' in your INSTALLED_APPS:
INSTALLED_APPS = [
    'django.contrib.admin',
    'django.contrib.auth',
    'django.contrib.contenttypes',
    'django.contrib.sessions',
    'django.contrib.messages',
    'django.contrib.staticfiles',
    
    # Add AIWAF app
    'aiwaf',
    
    # Your other apps...
]

# =============================================================================
# AI Dependencies (Optional)
# =============================================================================

# AIWAF works with or without these dependencies:
# - numpy
# - pandas
# - scikit-learn
# 
# If these are not installed, AIWAF will use JSON fallback storage
# and disable AI features automatically.
#
# To install AI dependencies:
# pip install numpy pandas scikit-learn

# =============================================================================
# Usage Examples
# =============================================================================

# To disable AI completely but keep other protection:
# AIWAF_DISABLE_AI = True
# AIWAF_ENABLE_KEYWORD_LEARNING = True
# AIWAF_ENABLE_IP_BLOCKING = True

# To run in minimal mode (no dependencies required):
# AIWAF_DISABLE_AI = True
# Don't install numpy, pandas, scikit-learn
# Only include IPAndKeywordBlockMiddleware in MIDDLEWARE

# To run with full AI protection:
# AIWAF_DISABLE_AI = False  (or omit this setting)
# Install all dependencies: pip install numpy pandas scikit-learn
# Include all middleware classes
