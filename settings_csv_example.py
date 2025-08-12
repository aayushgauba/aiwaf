# AI-WAF CSV Storage Configuration Example

# In your Django settings.py, add these configurations to use CSV-based storage
# instead of Django models for AI-WAF data.

# ============= CSV Storage Mode =============

# Set storage mode to CSV (default is "models")
AIWAF_STORAGE_MODE = "csv"

# Directory where CSV files will be stored (relative to Django project root)
AIWAF_CSV_DATA_DIR = "aiwaf_data"

# This will create the following CSV files:
# - aiwaf_data/blacklist.csv        # Blocked IP addresses
# - aiwaf_data/exemptions.csv       # Exempt IP addresses
# - aiwaf_data/keywords.csv         # Dynamic keywords with counts
# - aiwaf_data/access_samples.csv   # ML training feature samples

# ============= Required Settings =============

AIWAF_ACCESS_LOG = "/var/log/nginx/access.log"  # Path to your web server access log

# ============= Optional Settings =============

# AI and ML settings
AIWAF_AI_CONTAMINATION = 0.05     # AI anomaly detection sensitivity (5%)
AIWAF_MODEL_PATH = BASE_DIR / "aiwaf" / "resources" / "model.pkl"

# Timing and rate limiting
AIWAF_MIN_FORM_TIME = 1.0         # Minimum seconds between GET and POST
AIWAF_RATE_WINDOW = 10            # Rate limiting window in seconds  
AIWAF_RATE_MAX = 20               # Max requests per window
AIWAF_RATE_FLOOD = 10             # Flood detection threshold

# Detection windows
AIWAF_WINDOW_SECONDS = 60         # Anomaly detection window
AIWAF_DYNAMIC_TOP_N = 10          # Number of top dynamic keywords to use

# Path exemptions (these paths won't be blocked or analyzed)
AIWAF_EXEMPT_PATHS = [
    "/favicon.ico",
    "/robots.txt", 
    "/static/",
    "/media/",
    "/health/",
    "/api/webhooks/",  # Add your API endpoints that should never be blocked
]

# ============= CSV Mode Benefits =============

"""
CSV Mode Advantages:
1. No database migrations required
2. Easy to inspect and manually edit data files
3. Portable - can copy CSV files between environments
4. Simple backup - just backup the aiwaf_data directory
5. Version control friendly - can commit CSV files to git
6. Works without Django ORM dependencies
7. Faster for read-heavy workloads

CSV File Formats:
- blacklist.csv: ip_address,reason,created_at
- exemptions.csv: ip_address,reason,created_at  
- keywords.csv: keyword,count,last_updated
- access_samples.csv: ip,path_len,kw_hits,resp_time,status_idx,burst_count,total_404,label

All management commands work identically in both CSV and models mode:
- python manage.py add_ipexemption 192.168.1.100 --reason "Dev server"
- python manage.py aiwaf_reset --confirm
- python manage.py detect_and_train
"""

# ============= Models Mode (Alternative) =============

"""
If you prefer Django models instead of CSV:

AIWAF_STORAGE_MODE = "models"  # This is the default

Then run migrations:
python manage.py makemigrations aiwaf
python manage.py migrate

This creates database tables:
- aiwaf_blacklistentry
- aiwaf_ipexemption  
- aiwaf_dynamickeyword
- aiwaf_featuresample
"""
