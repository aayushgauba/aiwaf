# AI-WAF Django Installation Guide

This guide helps you properly install AI-WAF in your Django project to avoid common setup errors.

## 🚨 Common Error Fix

**Error:** `RuntimeError: Model class aiwaf.models.FeatureSample doesn't declare an explicit app_label and isn't in an application in INSTALLED_APPS.`

**Solution:** Follow the complete installation steps below.

## 📦 Step 1: Install AI-WAF

```bash
pip install aiwaf
```

## ⚙️ Step 2: Configure Django Settings

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
    'aiwaf.middleware.IPAndKeywordBlockMiddleware',
    'aiwaf.middleware.RateLimitMiddleware',
    'aiwaf.middleware.AIAnomalyMiddleware',
    'aiwaf.middleware.HoneypotTimingMiddleware',
    'aiwaf.middleware.UUIDTamperMiddleware',
    
    # Optional: AI-WAF Request Logger
    'aiwaf.middleware_logger.AIWAFLoggerMiddleware',
]
```

## 🗄️ Step 3: Database Setup

### **Django Models Setup**

```bash
# Create migrations
python manage.py makemigrations aiwaf

# Apply migrations
python manage.py migrate
```

All data is stored in Django models for real-time performance.

## 🚀 Step 4: Test Installation

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

## 🎯 Step 6: Start Training

```bash
# Train the AI model (after some traffic)
python manage.py detect_and_train
```

## 🛠️ Troubleshooting

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

## 📁 File Structure After Installation

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

## ✅ Verification Checklist

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
    'aiwaf.middleware.IPAndKeywordBlockMiddleware',  # Basic protection
]

# Choose one:
AIWAF_ACCESS_LOG = "/var/log/nginx/access.log"  # Use server logs
# OR
AIWAF_MIDDLEWARE_LOGGING = True  # Use built-in logger
```

```bash
# Run migrations (if using models)
python manage.py migrate

# Start protecting!
python manage.py runserver
```

That's it! AI-WAF is now protecting your Django application.
