# Example Django settings.py configuration for AI-WAF CSV mode

# AI-WAF Configuration
AIWAF_STORAGE_MODE = "csv"  # Use CSV files instead of database models
AIWAF_CSV_DATA_DIR = "aiwaf_data"  # Directory for CSV files

# Middleware logging (creates CSV request logs)
AIWAF_MIDDLEWARE_LOGGING = True
AIWAF_MIDDLEWARE_LOG = "aiwaf_requests.log"  # Will create aiwaf_requests.csv

# Add AI-WAF middlewares to MIDDLEWARE
MIDDLEWARE = [
    'django.middleware.security.SecurityMiddleware',
    'django.contrib.sessions.middleware.SessionMiddleware',
    'django.middleware.common.CommonMiddleware',
    'django.middleware.csrf.CsrfViewMiddleware',
    'django.contrib.auth.middleware.AuthenticationMiddleware',
    'django.contrib.messages.middleware.MessageMiddleware',
    'django.middleware.clickjacking.XFrameOptionsMiddleware',
    
    # AI-WAF Middlewares (add at the end)
    'aiwaf.middleware.IPAndKeywordBlockMiddleware',  # Core IP/keyword blocking
    'aiwaf.middleware.RateLimitMiddleware',          # Rate limiting
    'aiwaf.middleware.AIAnomalyMiddleware',          # AI-based anomaly detection
    'aiwaf.middleware_logger.AIWAFLoggerMiddleware', # Request logging for CSV mode
]

# Optional: Custom paths for logs
# AIWAF_ACCESS_LOG = "/path/to/your/access.log"  # Web server access log

# Directory structure that will be created:
# your_project/
# ├── aiwaf_data/
# │   ├── blacklist.csv
# │   ├── exemptions.csv
# │   └── keywords.csv
# └── aiwaf_requests.csv  # Middleware logs
