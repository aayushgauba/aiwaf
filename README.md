
# AI‑WAF

> A self‑learning, Django‑friendly Web Application Firewall  
> with **enhanced context-aware protection**, rate‑limiting, anomaly detection, honeypots, UUID‑tamper protection, **smart keyword learning**, file‑extension probing detection, exempt path awareness, and daily retraining.

**🆕 Latest Enhancements:**
- ✅ **Smart Keyword Filtering** - Prevents blocking legitimate pages like `/profile/`
- ✅ **Granular Reset Commands** - Clear specific data types (`--blacklist`, `--keywords`, `--exemptions`)
- ✅ **Context-Aware Learning** - Only learns from suspicious requests, not legitimate site functionality
- ✅ **Enhanced Configuration** - `AIWAF_ALLOWED_PATH_KEYWORDS` and `AIWAF_EXEMPT_KEYWORDS`
- ✅ **Comprehensive HTTP Method Validation** - Blocks GET→POST-only, POST→GET-only, unsupported REST methods
- ✅ **Enhanced Honeypot Protection** - POST validation & 4-minute page timeout with smart reload detection
- ✅ **HTTP Header Validation** - Comprehensive bot detection via header analysis and quality scoring

---

## 🚀 Quick Installation

```bash
pip install aiwaf
```

**⚠️ Important:** Add `'aiwaf'` to your Django `INSTALLED_APPS` to avoid setup errors.

**📋 Complete Setup Guide:** See [INSTALLATION.md](INSTALLATION.md) for detailed installation instructions and troubleshooting.

---

## System Requirements

No GPU needed—AI-WAF runs entirely on CPU with just Python 3.8+, Django 3.2+, a single vCPU and ~512 MB RAM for small sites; for moderate production traffic you can bump to 2–4 vCPUs and 2–4 GB RAM, offload the daily detect-and-train job to a worker, and rotate logs to keep memory use bounded.

## 📁 Package Structure

```
aiwaf/
├── __init__.py
├── blacklist_manager.py
├── middleware.py
├── trainer.py                   # exposes train()
├── utils.py
├── template_tags/
│   └── aiwaf_tags.py
├── resources/
│   ├── model.pkl                # pre‑trained base model
│   └── dynamic_keywords.json    # evolves daily
├── management/
│   └── commands/
│       ├── detect_and_train.py      # `python manage.py detect_and_train`
│       ├── add_ipexemption.py       # `python manage.py add_ipexemption`
│       ├── aiwaf_reset.py           # `python manage.py aiwaf_reset`
│       └── aiwaf_logging.py         # `python manage.py aiwaf_logging`
└── LICENSE
```

---

## 🚀 Features

- **IP Blocklist**  
  Instantly blocks suspicious IPs using Django models with real-time performance.

- **Rate Limiting**  
  Sliding‑window blocks flooders (> `AIWAF_RATE_MAX` per `AIWAF_RATE_WINDOW`), then blacklists them.

- **AI Anomaly Detection**  
  IsolationForest trained on:
  - Path length  

- **GeoIP Support**  
  AIWAF supports optional geo-blocking and country-level traffic statistics using a local GeoIP database.
  - Keyword hits (static + dynamic)  
  - Response time  
  - Status‑code index  
  - Burst count  
  - Total 404s  

- **Enhanced Dynamic Keyword Learning with Django Route Protection**  
  - **Smart Context-Aware Learning**: Only learns keywords from suspicious requests on non-existent paths
  - **Automatic Django Route Extraction**: Automatically excludes keywords from:
    - Valid Django URL patterns (`/profile/`, `/admin/`, `/api/`, etc.)
    - Django app names and model names (users, posts, categories)
    - View function names and URL namespaces
  - **Unified Logic**: Both trainer and middleware use identical legitimate keyword detection
  - **Configuration Options**: 
    - `AIWAF_ALLOWED_PATH_KEYWORDS` - Explicitly allow certain keywords in legitimate paths
    - `AIWAF_EXEMPT_KEYWORDS` - Keywords that should never trigger blocking
  - **Automatic Cleanup**: Keywords from `AIWAF_EXEMPT_PATHS` are automatically removed from the database
  - **False Positive Prevention**: Stops learning legitimate site functionality as "malicious"
  - **Inherent Malicious Detection**: Middleware also blocks obviously malicious keywords (`hack`, `exploit`, `attack`) even if not yet learned

- **File‑Extension Probing Detection**  
  Tracks repeated 404s on common extensions (e.g. `.php`, `.asp`) and blocks IPs.

- **🆕 HTTP Header Validation**
  Advanced header analysis to detect bots and malicious requests:
  - **Missing Required Headers** - Blocks requests without User-Agent or Accept headers
  - **Suspicious User-Agents** - Detects curl, wget, python-requests, automated tools
  - **Header Quality Scoring** - Calculates realism score based on browser-standard headers
  - **Legitimate Bot Whitelist** - Allows Googlebot, Bingbot, and other search engines
  - **Header Combination Analysis** - Detects impossible combinations (HTTP/2 + old browsers)
  - **Static File Exemption** - Skips validation for CSS, JS, images

## 🛡️ Header Validation Middleware Features

The **HeaderValidationMiddleware** provides advanced bot detection through HTTP header analysis:

### **What it detects:**
- **Missing Headers**: Requests without standard browser headers
- **Suspicious User-Agents**: WordPress scanners, exploit tools, basic scrapers
- **Bot-like Patterns**: Low header diversity, missing Accept headers
- **Quality Scoring**: 0-11 point system based on header completeness

### **What it allows:**
- **Legitimate Browsers**: Chrome, Firefox, Safari, Edge with full headers
- **Search Engine Bots**: Google, Bing, DuckDuckGo, Yandex crawlers
- **API Clients**: Properly identified with good headers
- **Static Files**: CSS, JS, images (automatically exempted)

### **Real-world effectiveness:**
```
✅ Blocks: WordPress scanners, exploit bots, basic scrapers
✅ Allows: Real browsers, legitimate bots, API clients
✅ Quality Score: 10/11 = Legitimate, 2/11 = Suspicious bot
```

### **Testing header validation:**
```bash
# Test with curl (will be blocked - low quality headers)
curl http://yoursite.com/

# Test with browser (will be allowed - high quality headers)
# Visit site normally in Chrome/Firefox

# Check logs for header validation blocks
python manage.py aiwaf_logging --recent
```

- **Enhanced Timing-Based Honeypot**  
  Advanced GET→POST timing analysis with comprehensive HTTP method validation:
  - Submit forms faster than `AIWAF_MIN_FORM_TIME` seconds (default: 1 second)
  - **🆕 Smart HTTP Method Validation** - Comprehensive protection against method misuse:
    - Blocks GET requests to POST-only views (form endpoints, API creates)
    - Blocks POST requests to GET-only views (list pages, read-only content)
    - Blocks unsupported REST methods (PUT/DELETE to non-REST views)
    - Uses Django view analysis: class-based views, method handlers, URL patterns
  - **🆕 Page expiration** after `AIWAF_MAX_PAGE_TIME` (4 minutes) with smart reload

- **UUID Tampering Protection**  
  Blocks guessed or invalid UUIDs that don't resolve to real models.

- **Built-in Request Logger**  
  Optional middleware logger that captures requests to Django models:
  - **Automatic fallback** when main access logs unavailable
  - **Real-time storage** in database for instant access
  - **Captures response times** for better anomaly detection
  - **Zero configuration** - works out of the box

- **Blocked Request Debug Logging**  
  Optional debug logs that explain why a request was blocked:
  - **Reason included** (keyword, flood pattern, AI anomaly, header validation, etc.)
  - **Request context** (IP, method, path, user agent)
  - **Disabled by default** - enable via Django `LOGGING`
  
  Example `settings.py`:
  ```python
  LOGGING = {
      "version": 1,
      "disable_existing_loggers": False,
      "handlers": {
          "console": {"class": "logging.StreamHandler"},
      },
      "loggers": {
          "aiwaf.middleware": {"handlers": ["console"], "level": "DEBUG"},
      },
  }
  ```

- **Blocked Request Responses**
  By default, AI‑WAF raises `PermissionDenied("blocked")` when a request is blocked,
  allowing Django to render a standard 403 page. For API clients that need JSON,
  add `JsonExceptionMiddleware` near the top of your `MIDDLEWARE` list; it will
  translate `PermissionDenied` into a JSON 403 response when
  `request.content_type == "application/json"`.

- **Smart Training System**  
  AI trainer automatically uses the best available data source:
  - **Primary**: Configured access log files (`AIWAF_ACCESS_LOG`)
  - **Fallback**: Database RequestLog model when files unavailable
  - **Seamless switching** between data sources
  - **Enhanced compatibility** with exemption system
  - **Minimum log thresholds**: AI training requires `AIWAF_MIN_AI_LOGS` (default 10,000); fewer logs falls back to keyword-only, which still requires `AIWAF_MIN_TRAIN_LOGS` (default 50)

**Exempt Path & IP Awareness**

**Exempt Paths:**
AI‑WAF automatically exempts common login paths (`/admin/`, `/login/`, `/accounts/login/`, etc.) from all blocking mechanisms. You can add additional exempt paths in your Django `settings.py`:

```python
AIWAF_EXEMPT_PATHS = [
    "/api/webhooks/",
    "/health/",
    "/special-endpoint/",
]
```

You can also store exempt paths in the database (no deploy needed):

```bash
python manage.py aiwaf_pathshell
```

Or add directly:

```bash
python manage.py add_pathexemption /myapp/api/ --reason "API traffic"
```

**AIWAF Path Shell Commands:**
```
ls                     # list routes at current level
cd <index|name>        # enter a route segment
up / cd ..             # go up one level
pwd                    # show current path prefix
exempt <index|name|.>  # add exemption for selection or current path
exit                   # quit
```


**Exempt Path & IP Awareness**

**Exempt Paths:**
AI‑WAF automatically exempts common login paths (`/admin/`, `/login/`, `/accounts/login/`, etc.) from all blocking mechanisms. You can add additional exempt paths in your Django `settings.py`:

```python
AIWAF_EXEMPT_PATHS = [
    "/api/webhooks/",
    "/health/",
    "/special-endpoint/",
]
```

You can also store exempt paths in the database (no deploy needed):

```bash
python manage.py aiwaf_pathshell
```

Or add directly:

```bash
python manage.py add_pathexemption /myapp/api/ --reason "API traffic"
```

**AIWAF Path Shell Commands:**
```
ls                     # list routes at current level
cd <index|name>        # enter a route segment
up / cd ..             # go up one level
pwd                    # show current path prefix
exempt <index|name|.>  # add exemption for selection or current path
exit                   # quit
```

**Exempt Views (Decorator):**
Use the `@aiwaf_exempt` decorator to exempt specific views from all AI-WAF protection:

```python
from aiwaf.decorators import aiwaf_exempt
from django.http import JsonResponse

@aiwaf_exempt
def my_api_view(request):
    """This view will be exempt from all AI-WAF protection"""
    return JsonResponse({"status": "success"})

# Works with class-based views too
@aiwaf_exempt
class MyAPIView(View):
    def get(self, request):
        return JsonResponse({"method": "GET"})
```

All exempt paths and views are:
  - Skipped from keyword learning
  - Immune to AI blocking
  - Ignored in log training
  - Cleaned from `DynamicKeyword` model automatically

**Exempt IPs:**
You can exempt specific IP addresses from all blocking and blacklisting logic. Exempted IPs will:
  - Never be added to the blacklist (even if they trigger rules)
  - Be automatically removed from the blacklist during retraining
  - Bypass all block/deny logic in middleware

### Managing Exempt IPs

Add an IP to the exemption list using the management command:

```bash
python manage.py add_ipexemption <ip-address> --reason "optional reason"
```

### Resetting AI-WAF

The `aiwaf_reset` command provides **granular control** for clearing different types of data:

```bash
# Clear everything (default - backward compatible)
python manage.py aiwaf_reset

# Clear everything without confirmation prompt
python manage.py aiwaf_reset --confirm

# 🆕 GRANULAR CONTROL - Clear specific data types
python manage.py aiwaf_reset --blacklist      # Clear only blocked IPs
python manage.py aiwaf_reset --exemptions     # Clear only exempted IPs  
python manage.py aiwaf_reset --keywords       # Clear only learned keywords

# 🔧 COMBINE OPTIONS - Mix and match as needed
python manage.py aiwaf_reset --blacklist --keywords      # Keep exemptions
python manage.py aiwaf_reset --exemptions --keywords     # Keep blacklist
python manage.py aiwaf_reset --blacklist --exemptions    # Keep keywords

# 🚀 COMMON USE CASES
# Fix false positive keywords (like "profile" blocking legitimate pages)
python manage.py aiwaf_reset --keywords --confirm
python manage.py detect_and_train  # Retrain with enhanced filtering

# Clear blocked IPs but preserve exemptions and learning
python manage.py aiwaf_reset --blacklist --confirm

# Legacy support (still works for backward compatibility)
python manage.py aiwaf_reset --blacklist-only    # Legacy: blacklist only
python manage.py aiwaf_reset --exemptions-only   # Legacy: exemptions only
```

**Enhanced Feedback:**
```bash
$ python manage.py aiwaf_reset --keywords
🔧 AI-WAF Reset: Clear 15 learned keywords
Are you sure you want to proceed? [y/N]: y
✅ Reset complete: Deleted 15 learned keywords
```

This will ensure the IP is never blocked by AI‑WAF. You can also manage exemptions via the Django admin interface.

- **Daily Retraining**  
  Reads rotated logs, auto‑blocks 404 floods, retrains the IsolationForest, updates `model.pkl`, and evolves the keyword DB.
  If GeoIP is enabled, it also prints a country summary for anomalous IPs.

---

## ⚙️ Configuration (`settings.py`)

```python
INSTALLED_APPS += ["aiwaf"]
```

### Database Setup

After adding `aiwaf` to your `INSTALLED_APPS`, run the following to create the necessary tables:

```bash
python manage.py makemigrations aiwaf
python manage.py migrate
```

---

### Required

```python
AIWAF_ACCESS_LOG = "/var/log/nginx/access.log"
```

---

### Database Models

AI-WAF uses Django models for real-time, high-performance storage:

```python
# All data is stored in Django models - no configuration needed
# Tables created automatically with migrations:
# - aiwaf_blacklistentry     # Blocked IP addresses
# - aiwaf_ipexemption        # Exempt IP addresses  
# - aiwaf_exemptpath         # Exempt path prefixes
# - aiwaf_dynamickeyword     # Dynamic keywords with counts
# - aiwaf_featuresample      # Feature samples for ML training
# - aiwaf_requestlog         # Request logs (if middleware logging enabled)
```

**Benefits of Django Models:**
- ⚡ **Real-time performance** - No file I/O bottlenecks
- 🔄 **Instant updates** - Changes visible immediately across all processes
- 🚀 **Better concurrency** - No file locking issues
- 📊 **Rich querying** - Use Django ORM for complex operations
- 🔍 **Admin integration** - View/manage data through Django admin

**Database Setup:**
```bash
# Create and apply migrations
python manage.py makemigrations aiwaf
python manage.py migrate aiwaf
```

---

### Built-in Request Logger (Optional)

Enable AI-WAF's built-in request logger as a fallback when main access logs aren't available:

```python
# Enable middleware logging
AIWAF_MIDDLEWARE_LOGGING = True                    # Enable/disable logging
AIWAF_MIDDLEWARE_LOG = "aiwaf_requests.log"        # Optional log file name
AIWAF_MIDDLEWARE_CSV = True                        # Write CSV log file (default: True)
AIWAF_MIDDLEWARE_DB = True                         # Write RequestLog entries (default: True)
AIWAF_USE_RUST = False                             # Use Rust backend when CSV logging is enabled
```

**Then add middleware to MIDDLEWARE list:**

```python
MIDDLEWARE = [
    # ... your existing middleware ...
    'aiwaf.middleware_logger.AIWAFLoggerMiddleware',  # Add near the end
]
```

**Manage middleware logging:**

```bash
python manage.py aiwaf_logging --status    # Check logging status
python manage.py aiwaf_logging --enable    # Show setup instructions  
python manage.py aiwaf_logging --clear     # Clear log files
```

**Benefits:**
- **Automatic fallback** when `AIWAF_ACCESS_LOG` unavailable
- **CSV or database storage** with precise timestamps and response times
- **Zero configuration** - trainer automatically detects and uses model logs
- **Lightweight** - fails silently to avoid breaking your application

If you want the trainer to use the CSV log file, point `AIWAF_ACCESS_LOG` at the CSV path (e.g., `aiwaf_requests.csv`).

---

### Optional Rust Backend (CSV + Header Validation)

When both `AIWAF_MIDDLEWARE_CSV = True` and `AIWAF_USE_RUST = True`, AI-WAF uses a Rust
backend (pyo3/maturin) for header validation and CSV logging. If the Rust module is not
available, it automatically falls back to the Python implementation.

**Build the Rust extension:**
```bash
pip install maturin
maturin develop -m aiwaf_rust/Cargo.toml
```

**Enable in settings:**
```python
AIWAF_MIDDLEWARE_CSV = True
AIWAF_USE_RUST = True
```

---

### Optional (defaults shown)

```python
AIWAF_MODEL_PATH         = BASE_DIR / "aiwaf" / "resources" / "model.pkl"
AIWAF_MODEL_STORAGE      = "file"    # file | db | cache
AIWAF_MODEL_CACHE_KEY    = "aiwaf:model"
AIWAF_MODEL_CACHE_TIMEOUT = None     # seconds; None for no expiry
AIWAF_MODEL_STORAGE_FALLBACK = True  # fallback to file when db/cache unavailable
AIWAF_MIN_FORM_TIME      = 1.0        # minimum seconds between GET and POST
AIWAF_MAX_PAGE_TIME      = 240        # maximum page age before requiring reload (4 minutes)
AIWAF_AI_CONTAMINATION   = 0.05       # AI anomaly detection sensitivity (5%)
AIWAF_MIN_AI_LOGS        = 10000      # minimum log lines for AI training
AIWAF_MIN_TRAIN_LOGS     = 50         # minimum log lines for keyword training
AIWAF_FORCE_AI_TRAINING  = False      # override AIWAF_MIN_AI_LOGS gate
AIWAF_RATE_WINDOW        = 10         # seconds
AIWAF_RATE_MAX           = 20         # max requests per window
AIWAF_RATE_FLOOD         = 10         # flood threshold
AIWAF_WINDOW_SECONDS     = 60         # anomaly detection window
AIWAF_FILE_EXTENSIONS    = [".php", ".asp", ".jsp"]

# Geo-blocking (optional, requires aiwaf[geoblock])
AIWAF_GEO_BLOCK_ENABLED  = False
AIWAF_GEOIP_DB_PATH      = "aiwaf/geolock/ipinfo_lite.mmdb"
AIWAF_GEO_BLOCK_COUNTRIES = ["CN", "RU"]
AIWAF_GEO_ALLOW_COUNTRIES = []        # If set, only these countries are allowed
AIWAF_GEO_CACHE_SECONDS  = 3600
AIWAF_GEO_CACHE_PREFIX   = "aiwaf:geo:"
AIWAF_EXEMPT_PATHS = [          # optional but highly recommended
    "/favicon.ico",
    "/robots.txt",
    "/static/",
    "/media/",
    "/health/",
]

# 🆕 ENHANCED KEYWORD FILTERING OPTIONS
AIWAF_ALLOWED_PATH_KEYWORDS = [  # Keywords allowed in legitimate paths
    "profile", "user", "account", "settings", "dashboard",
    "admin", "api", "auth", "search", "contact", "about",
    # Add your site-specific legitimate keywords
    "buddycraft", "sc2", "starcraft",  # Example: gaming site keywords
]

AIWAF_EXEMPT_KEYWORDS = [        # Keywords that never trigger blocking
    "api", "webhook", "health", "static", "media",
    "upload", "download", "backup", "profile"
]

AIWAF_DYNAMIC_TOP_N = 10        # Number of dynamic keywords to learn (default: 10)
```

> **Note:** You no longer need to define `AIWAF_MALICIOUS_KEYWORDS` or `AIWAF_STATUS_CODES` — they evolve dynamically.

**Model storage options:**
- `file` (default) writes to `AIWAF_MODEL_PATH`
- `db` stores the model in the `AIModelArtifact` table (run migrations)
- `cache` stores the model in your Django cache backend

### Installation Modes

Full install (default) includes AI training and GeoIP support:

```bash
pip install aiwaf
```

Light install (manual deps only):

```bash
pip install aiwaf --no-deps
pip install "Django>=3.2" "requests>=2.25.0"
```

Geo-blocking uses the bundled `.mmdb` file by default. Set `AIWAF_GEOIP_DB_PATH` to override.

**GeoBlock Middleware:**
Enable the middleware and the feature flag:

```python
AIWAF_GEO_BLOCK_ENABLED = True
```

```python
MIDDLEWARE = [
    "aiwaf.middleware.JsonExceptionMiddleware",   # Optional: JSON error responses for API clients
    "aiwaf.middleware.GeoBlockMiddleware",
    # ... other AI-WAF middleware ...
]
```

### Acknowledgements

Geo-blocking functionality in AIWAF relies on the IPinfo MMDB for IP-to-country mapping.  
Thanks to IPinfo for providing a reliable GeoIP database.    

**Dynamic country blocking (database-backed):**

```bash
python manage.py geo_block_country list
python manage.py geo_block_country add US
python manage.py geo_block_country remove US
```

### Path-Specific Rules

Use path rules to selectively disable middleware or override settings without
full exemptions:

```python
AIWAF_SETTINGS = {
  "PATH_RULES": [
    {
      "PREFIX": "/myapp/api/",
      "DISABLE": ["HeaderValidationMiddleware"],
      "RATE_LIMIT": {"WINDOW": 60, "MAX": 2000},
    },
    {
      "PREFIX": "/myapp/",
      "RATE_LIMIT": {"WINDOW": 60, "MAX": 200},
    },
  ]
}
```

Each middleware checks `request.path`, computes the effective policy, then
applies or skips accordingly.

Define `PATH_RULES` in your Django settings file (e.g. `settings.py`) under
`AIWAF_SETTINGS`.

### Legacy `AIWAF_SETTINGS` Compatibility

If you already use the nested `AIWAF_SETTINGS` dict, AI-WAF will map common keys into the flat `AIWAF_*` settings at startup (without overriding explicit `AIWAF_*` values). Supported mappings include `RATE_LIMITING`, `EXEMPTIONS.PATHS`, `IP_BLOCKING.ENABLED`, `KEYWORD_DETECTION` (custom patterns + sensitivity), and `LOGGING.ENABLED`.

---

## 🧱 Middleware Setup

Add in **this** order to your `MIDDLEWARE` list:

```python
MIDDLEWARE = [
    "aiwaf.middleware.JsonExceptionMiddleware",   # Optional: JSON error responses for API clients
    "aiwaf.middleware.GeoBlockMiddleware",
    "aiwaf.middleware.IPAndKeywordBlockMiddleware",
    "aiwaf.middleware.RateLimitMiddleware", 
    "aiwaf.middleware.AIAnomalyMiddleware",
    "aiwaf.middleware.HoneypotTimingMiddleware",
    "aiwaf.middleware.UUIDTamperMiddleware",
    # ... other middleware ...
    "aiwaf.middleware_logger.AIWAFLoggerMiddleware",  # Optional: Add if using built-in logger
]
```

> **⚠️ Order matters!** AI-WAF protection middleware should come early. The logger middleware should come near the end to capture final response data.
> **JSON APIs:** If you want JSON error bodies on `PermissionDenied`, add `JsonExceptionMiddleware` near the top so it runs last during exception handling.

**UUIDTamperMiddleware behavior:**
- Only checks models in the view's app that have UUID primary keys or unique UUID fields.
- If an app has no such models, the middleware is a no-op for that request.

### **Troubleshooting Middleware Errors**

**Error: `Module "aiwaf.middleware" does not define a "UUIDTamperMiddleware" attribute/class`**

**Solutions:**
1. **Update AI-WAF to latest version:**
   ```bash
   pip install --upgrade aiwaf
   ```

2. **Run diagnostic commands:**
   ```bash
   # Quick debug script (from AI-WAF directory)
   python debug_aiwaf.py
   
   # Django management command  
   python manage.py aiwaf_diagnose
   ```

3. **Check available middleware classes:**
   ```python
   # In Django shell: python manage.py shell
   import aiwaf.middleware
   print(dir(aiwaf.middleware))
   ```

4. **Verify AI-WAF is in INSTALLED_APPS:**
   ```python
   # In settings.py
   INSTALLED_APPS = [
       # ... other apps ...
       'aiwaf',  # Must be included
   ]
   ```

5. **Use minimal middleware setup if needed:**
   ```python
MIDDLEWARE = [
    # ... your existing middleware ...
    "aiwaf.middleware.JsonExceptionMiddleware",   # Optional: JSON error responses for API clients
    "aiwaf.middleware.IPAndKeywordBlockMiddleware",  # Core protection
    "aiwaf.middleware.RateLimitMiddleware",          # Rate limiting  
    "aiwaf.middleware.AIAnomalyMiddleware",          # AI detection
]
   ```

**Common Issues:**
- **AppRegistryNotReady Error**: Fixed in v0.1.9.0.1 - update with `pip install --upgrade aiwaf`
- **Scikit-learn Version Warnings**: Fixed in v0.1.9.0.3 - regenerate model with `python manage.py regenerate_model`
- Missing Django: `pip install Django`
- Old AI-WAF version: `pip install --upgrade aiwaf`
- Missing migrations: `python manage.py migrate`
- Import errors: Check `INSTALLED_APPS` includes `'aiwaf'`


---

##  Running Detection & Training

```bash
python manage.py detect_and_train
```

### What happens:
1. Read access logs (incl. rotated or gzipped) **OR** AI-WAF middleware model logs
2. Auto‑block IPs with ≥ 6 total 404s
3. Extract features & train IsolationForest
4. Save `model.pkl` with current scikit-learn version

### Model Regeneration

If you see scikit-learn version warnings, regenerate the model:

```bash
# Quick model regeneration (recommended)
python manage.py regenerate_model

# Full retraining with fresh data
python manage.py detect_and_train
```

**Benefits:**
- ✅ Eliminates version compatibility warnings
- ✅ Uses current scikit-learn optimizations
- ✅ Maintains same protection level
4. Save `model.pkl`
5. Extract top 10 dynamic keywords from 4xx/5xx
6. Remove any keywords associated with newly exempt paths

**Note:** If main access log (`AIWAF_ACCESS_LOG`) is unavailable, trainer automatically falls back to AI-WAF middleware model logs.

---

## 🧠 How It Works
```

---

##  Running Detection & Training

```bash
python manage.py detect_and_train
```

### What happens:
1. Read access logs (incl. rotated or gzipped)
2. Auto‑block IPs with ≥ 6 total 404s
3. Extract features & train IsolationForest
4. Save `model.pkl`
5. Extract top 10 dynamic keywords from 4xx/5xx
6. Remove any keywords associated with newly exempt paths

---

## 🔧 Troubleshooting

### Legitimate Pages Being Blocked

**Problem**: Users can't access legitimate pages like `/en/profile/` due to keyword blocking.

**Cause**: AIWAF learned legitimate keywords (like "profile") as suspicious from previous traffic.

**Solution**:
```bash
# 1. Clear problematic learned keywords
python manage.py aiwaf_reset --keywords --confirm

# 2. Add legitimate keywords to settings
# In settings.py:
AIWAF_ALLOWED_PATH_KEYWORDS = [
    "profile", "user", "account", "dashboard",
    # Add your site-specific keywords
]

# 3. Retrain with enhanced filtering (won't learn legitimate keywords)
python manage.py detect_and_train

# 4. Test - legitimate pages should now work!
```

### Preventing Future False Positives

Configure AIWAF to recognize your site's legitimate keywords:

```python
# settings.py
AIWAF_ALLOWED_PATH_KEYWORDS = [
    # Common legitimate keywords
    "profile", "user", "account", "settings", "dashboard",
    "admin", "search", "contact", "about", "help",
    
    # Your site-specific keywords
    "buddycraft", "sc2", "starcraft",  # Gaming site example
    "shop", "cart", "checkout",        # E-commerce example  
    "blog", "article", "news",         # Content site example
]
```

### Reset Command Options

```bash
# Clear everything (safest for troubleshooting)
python manage.py aiwaf_reset --confirm

# Clear only problematic keywords
python manage.py aiwaf_reset --keywords --confirm

# Clear blocked IPs but keep exemptions
python manage.py aiwaf_reset --blacklist --confirm
```

---

## 🧠 How It Works

| Middleware                         | Purpose                                                         |
|------------------------------------|-----------------------------------------------------------------|
| GeoBlockMiddleware                 | Blocks traffic by country based on GeoIP database               |
| IPAndKeywordBlockMiddleware        | Blocks requests from known blacklisted IPs and Keywords         |
| RateLimitMiddleware                | Enforces burst & flood thresholds                               |
| AIAnomalyMiddleware                | ML‑driven behavior analysis + block on anomaly                  |
| HoneypotTimingMiddleware           | Enhanced bot detection: GET→POST timing, POST validation, page timeouts |
| UUIDTamperMiddleware               | Blocks guessed/nonexistent UUIDs across models with UUID PKs or unique UUID fields in an app (no-op if none) |
| HeaderValidationMiddleware         | Blocks suspicious header patterns and low‑quality user agents   |
| AIWAFLoggerMiddleware              | Optional request logger for model training and analysis         |

### 🍯 Enhanced Honeypot Protection

The **HoneypotTimingMiddleware** now includes advanced bot detection capabilities:

#### 🚫 Smart POST Request Validation
- **Analyzes Django views** to determine actual allowed HTTP methods
- **Intelligent detection** of GET-only vs POST-capable views
- **Example**: `POST` to view with `http_method_names = ['get']` → `PermissionDenied (403)`

#### ⏰ Page Timeout with Smart Reload
- **4-minute page expiration** prevents stale session attacks
- **HTTP 409 response** with reload instructions instead of immediate blocking
- **CSRF protection** by forcing fresh page loads for old sessions

```python
# Configuration
AIWAF_MIN_FORM_TIME = 1.0     # Minimum form submission time
AIWAF_MAX_PAGE_TIME = 240     # Page timeout (4 minutes)
```

**Timeline Example**:
```
12:00:00 - GET /contact/   ✅ Page loaded
12:02:00 - POST /contact/  ✅ Valid submission (2 minutes)
12:04:30 - POST /contact/  ❌ 409 Conflict (page expired, reload required)
```

---

## Sponsors

This project is proudly supported by:

<a href="https://www.digitalocean.com/">
  <img src="https://opensource.nyc3.cdn.digitaloceanspaces.com/attribution/assets/SVG/DO_Logo_horizontal_blue.svg" width="201px">
</a>

[DigitalOcean](https://www.digitalocean.com/) provides the cloud infrastructure that powers AIWAF development.

---

## License

This project is licensed under the **MIT License**. See the [LICENSE](LICENSE) file for details.

---

