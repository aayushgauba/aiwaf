# AI-WAF Django Installation Guide

This guide helps you properly install AI-WAF in your Django project to avoid common setup errors.

## Common Error Fix

**Error:** `RuntimeError: Model class aiwaf.models.FeatureSample doesn't declare an explicit app_label and isn't in an application in INSTALLED_APPS.`

**Solution:** Follow the complete installation steps below.

## Step 1: Install AI-WAF

```bash
pip install aiwaf
```

## Step 2: Configure Django Settings

Add AI-WAF to your Django project's `settings.py`:

### **Required: Add to INSTALLED_APPS**

```python
# settings.py

INSTALLED_APPS = [
    'django.contrib.admin',
    'django.contrib.auth',
    'django.contrib.contenttypes',
    'django.contrib.sessions',
    'django.contrib.messages',
    'django.contrib.staticfiles',
    
    # Your apps
    'your_app',
    
    # AI-WAF (REQUIRED - must be in INSTALLED_APPS)
    'aiwaf',
]
```

### **Required: Basic Configuration**

```python
# AI-WAF Configuration
AIWAF_ACCESS_LOG = "/var/log/nginx/access.log"  # Path to your access log
```

### **Required: Add Middleware**

```python
# settings.py

MIDDLEWARE = [
    'django.middleware.security.SecurityMiddleware',
    'django.contrib.sessions.middleware.SessionMiddleware',
    'django.middleware.common.CommonMiddleware',
    'django.middleware.csrf.CsrfViewMiddleware',
    'django.contrib.auth.middleware.AuthenticationMiddleware',
    'django.contrib.messages.middleware.MessageMiddleware',
    
    # AI-WAF Protection Middleware (add these)
    'aiwaf.middleware.JsonExceptionMiddleware',   # Optional: JSON error responses for API clients
    'aiwaf.middleware.IPAndKeywordBlockMiddleware',
    'aiwaf.middleware.HeaderValidationMiddleware',
    'aiwaf.middleware.RateLimitMiddleware',
    'aiwaf.middleware.AIAnomalyMiddleware',
    'aiwaf.middleware.HoneypotTimingMiddleware',
    'aiwaf.middleware.UUIDTamperMiddleware',
    
    # Optional: AI-WAF Request Logger
    'aiwaf.middleware_logger.AIWAFLoggerMiddleware',
]
```

**Middleware Order Explanation:**
- **JsonExceptionMiddleware**: Optional JSON error bodies for `PermissionDenied` on API requests (place early)
- **HeaderValidationMiddleware**: Should be first among AI-WAF middlewares for early bot detection
- **IPAndKeywordBlockMiddleware**: Core IP and keyword blocking
- **RateLimitMiddleware**: Rate limiting protection  
- **AIAnomalyMiddleware**: AI-based anomaly detection
- **HoneypotTimingMiddleware**: Form timing analysis
- **UUIDTamperMiddleware**: UUID tampering detection
- **AIWAFLoggerMiddleware**: Request logging (optional, can be last)

## Step 3: Database Setup

### **Django Models Setup**

```bash
# Create migrations
python manage.py makemigrations aiwaf

# Apply migrations
python manage.py migrate
```

All data is stored in Django models for real-time performance.

## Step 4: Test Installation

```bash
# Test the installation
python manage.py check

# Add a test IP exemption
python manage.py add_ipexemption 127.0.0.1 --reason "Testing"

# Check AI-WAF status
python manage.py aiwaf_logging --status
```

## 🔧 Step 5: Optional Configuration

### **Enable Built-in Request Logger**

```python
# settings.py
AIWAF_MIDDLEWARE_LOGGING = True
```

### **Exempt Paths**

```python
# settings.py
AIWAF_EXEMPT_PATHS = [
    "/favicon.ico",
    "/robots.txt",
    "/static/",
    "/media/",
    "/health/",
    "/api/webhooks/",
]
```

### **AI Settings**

```python
# settings.py
AIWAF_AI_CONTAMINATION = 0.05  # AI sensitivity (5%)
AIWAF_MIN_FORM_TIME = 1.0      # Honeypot timing
AIWAF_RATE_MAX = 20            # Rate limiting
```

### **Header Validation Settings**

```python
# settings.py - HTTP Header Bot Detection Configuration

# Enable/disable header validation (default: True)
AIWAF_HEADER_VALIDATION_ENABLED = True

# Minimum header quality score (default: 5, range: 0-11)
AIWAF_MIN_HEADER_QUALITY = 5

# Block requests with suspicious User-Agent patterns (default: True)
AIWAF_BLOCK_SUSPICIOUS_USER_AGENTS = True

# Allow legitimate bots (Google, Bing, etc.) even with low scores (default: True)
AIWAF_ALLOW_LEGITIMATE_BOTS = True

# Log blocked header validation requests (default: True)
AIWAF_LOG_HEADER_BLOCKS = True

# Custom suspicious User-Agent patterns (regex)
AIWAF_CUSTOM_SUSPICIOUS_PATTERNS = [
    r'wordpress',
    r'scanner',
    r'exploit',
    # Add your patterns here
]

# Whitelist additional legitimate bot User-Agents
AIWAF_LEGITIMATE_BOT_PATTERNS = [
    r'MyCustomBot/1.0',
    r'LegitimateScanner',
    # Add your patterns here  
]
```

## Step 6: Start Training

```bash
# Train the AI model (after some traffic)
python manage.py detect_and_train
```

**Light install (manual deps only):**

```bash
pip install aiwaf --no-deps
pip install "Django>=3.2" "requests>=2.25.0"
```

**Training thresholds:** AI training runs when there are at least `AIWAF_MIN_AI_LOGS` (default 10,000) log lines. If fewer logs are available, AI training is skipped and keyword-only training runs as long as there are at least `AIWAF_MIN_TRAIN_LOGS` (default 50). Set `AIWAF_FORCE_AI_TRAINING = True` to override the AI log threshold.


## Troubleshooting

### **Error: Model not in INSTALLED_APPS**

**Problem:** AI-WAF models can't be loaded.

**Solutions:**
1. Add `'aiwaf'` to `INSTALLED_APPS` (required)
2. Run `python manage.py migrate` if using models
3. Use CSV mode: `AIWAF_STORAGE_MODE = "csv"`

### **Error: No module named 'aiwaf'**

**Problem:** AI-WAF not installed properly.

**Solution:**
```bash
pip install aiwaf
# or
pip install --upgrade aiwaf
```

### **Error: Access log not found**

**Problem:** `AIWAF_ACCESS_LOG` points to non-existent file.

**Solutions:**
1. Fix log path in settings
2. Enable middleware logger: `AIWAF_MIDDLEWARE_LOGGING = True`

## File Structure After Installation

### **Django Models Storage:**
```
your_project/
├── manage.py
├── settings.py
├── db.sqlite3 (contains aiwaf tables)
└── aiwaf_requests.log (if middleware logging enabled)
```

### **CSV Mode:**
```
your_project/
├── manage.py  
├── settings.py
└── db.sqlite3               # Contains AI-WAF model tables
```

**Database Tables Created:**
- `aiwaf_blacklistentry` - Blocked IP addresses
- `aiwaf_ipexemption` - Exempt IP addresses  
- `aiwaf_dynamickeyword` - Dynamic keywords with counts
- `aiwaf_featuresample` - Feature samples for ML training
- `aiwaf_requestlog` - Request logs (if middleware logging enabled)
```

## Optional Rust Backend (CSV + Header Validation)

When both `AIWAF_MIDDLEWARE_CSV = True` and `AIWAF_USE_RUST = True`, AI-WAF uses a Rust
backend (pyo3/maturin) for header validation and CSV logging. If the Rust module is not
available, it falls back to Python automatically.

```bash
pip install maturin
maturin develop -m aiwaf_rust/Cargo.toml
```

```python
AIWAF_MIDDLEWARE_CSV = True
AIWAF_USE_RUST = True
```

## Verification Checklist

- [ ] `aiwaf` added to `INSTALLED_APPS`
- [ ] `AIWAF_ACCESS_LOG` configured
- [ ] Middleware added to `MIDDLEWARE`
- [ ] Migrations run: `python manage.py migrate aiwaf`
- [ ] `python manage.py check` passes
- [ ] Test command works: `python manage.py add_exemption 127.0.0.1`

## 🏃‍♂️ Quick Start (Minimal Setup)

```python
# settings.py - Minimal configuration

INSTALLED_APPS = [
    # ... existing apps ...
    'aiwaf',  # Required
]

MIDDLEWARE = [
    # ... existing middleware ...
    'aiwaf.middleware.JsonExceptionMiddleware',      # Optional: JSON error responses for API clients
    'aiwaf.middleware.HeaderValidationMiddleware',   # Bot detection (recommended first)
    'aiwaf.middleware.IPAndKeywordBlockMiddleware',  # Basic protection
]

# Choose one:
AIWAF_ACCESS_LOG = "/var/log/nginx/access.log"  # Use server logs
# OR
AIWAF_MIDDLEWARE_LOGGING = True  # Use built-in logger

# Optional: Configure header validation
AIWAF_MIN_HEADER_QUALITY = 5  # Block requests with low header quality
```

```bash
# Run migrations (if using models)
python manage.py migrate

# Start protecting!
python manage.py runserver
```

That's it! AI-WAF is now protecting your Django application.
