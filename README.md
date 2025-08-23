
# AI‑WAF

> A self‑learning, Django‑friendly Web Application Firewall  
> with **enhanced context-aware protection**, rate‑limiting, anomaly detection, honeypots, UUID‑tamper protection, **smart keyword learning**, file‑extension probing detection, exempt path awareness, and daily retraining.

**🆕 Latest Enhancements:**
- ✅ **Smart Keyword Filtering** - Prevents blocking legitimate pages like `/profile/`
- ✅ **Granular Reset Commands** - Clear specific data types (`--blacklist`, `--keywords`, `--exemptions`)
- ✅ **Context-Aware Learning** - Only learns from suspicious requests, not legitimate site functionality
- ✅ **Enhanced Configuration** - `AIWAF_ALLOWED_PATH_KEYWORDS` and `AIWAF_EXEMPT_KEYWORDS`

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
│       ├── check_dependencies.py    # `python manage.py check_dependencies`
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

- **Timing-Based Honeypot**  
  Tracks GET→POST timing patterns. Blocks IPs that:
  - POST directly without a preceding GET request
  - Submit forms faster than `AIWAF_MIN_FORM_TIME` seconds (default: 1 second)

- **UUID Tampering Protection**  
  Blocks guessed or invalid UUIDs that don't resolve to real models.

- **Built-in Request Logger**  
  Optional middleware logger that captures requests to Django models:
  - **Automatic fallback** when main access logs unavailable
  - **Real-time storage** in database for instant access
  - **Captures response times** for better anomaly detection
  - **Zero configuration** - works out of the box

- **Smart Training System**  
  AI trainer automatically uses the best available data source:
  - **Primary**: Configured access log files (`AIWAF_ACCESS_LOG`)
  - **Fallback**: Database RequestLog model when files unavailable
  - **Seamless switching** between data sources
  - **Enhanced compatibility** with exemption system

- **Dependency Management**  
  Built-in dependency checker ensures package compatibility:
  - **Version compatibility** checking (NumPy 2.0 vs pandas, etc.)
  - **Missing dependency** detection
  - **Security vulnerability** scanning
  - **Smart upgrade suggestions** with compatibility validation
  - **Safe automated upgrades** that preserve AIWAF stability
  - **Dry run mode** for testing upgrade plans
  - **Cross-package dependency** analysis and conflict resolution


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

### Checking Dependencies

Check your project's dependencies for updates and compatibility issues:

```bash
# Basic dependency check
python manage.py check_dependencies

# JSON format output
python manage.py check_dependencies --format json

# Include security vulnerability scanning
python manage.py check_dependencies --check-security

# Dry run - show what would be upgraded
python manage.py check_dependencies --upgrade --dry-run

# Actually upgrade packages safely
python manage.py check_dependencies --upgrade

# Upgrade packages and update requirements.txt
python manage.py check_dependencies --upgrade --update-requirements

# Full workflow: check, upgrade, and scan for vulnerabilities
python manage.py check_dependencies --upgrade --check-security --update-requirements
```

**Core Features:**
- ✅ **Parses pyproject.toml and requirements.txt**
- ✅ **Shows current vs latest versions** 
- ✅ **Checks package compatibility** (NumPy 2.0 vs pandas, etc.)
- ✅ **Detects missing dependencies**
- ✅ **Security vulnerability scanning** (requires `safety` package)
- ✅ **Safe package upgrades** (maintains AIWAF stability)
- ✅ **Dry run mode** for testing upgrade plans
- ✅ **AIWAF compatibility validation**
- ✅ **Automatic requirements.txt updates** after successful upgrades
- ✅ **Pip cache clearing** to prevent cache-related issues

**Safe Upgrade System:**

The upgrade system is designed to maintain AIWAF stability while keeping your packages up to date:

| Protection Level | Description | Example |
|------------------|-------------|---------|
| 🛡️ **AIWAF Core** | Never upgrades AIWAF itself | Skips `aiwaf` package |
| 🔒 **Breaking Changes** | Avoids known problematic versions | Blocks NumPy 2.0+ |
| 🧠 **Smart Constraints** | Respects AIWAF compatibility matrix | pandas ≤ 2.9.99 |
| 🔍 **Dependency Analysis** | Checks cross-package compatibility | NumPy vs pandas versions |

**AIWAF Compatibility Matrix:**

| Package | Safe Range | Blocked Versions | Reason |
|---------|------------|------------------|---------|
| Django | 3.2+ | None | AIWAF compatible with all Django versions |
| NumPy | 1.21 - 1.99 | 2.0+ | Avoid breaking changes |
| pandas | 1.3 - 2.9 | 3.0+ | AIWAF compatibility |
| scikit-learn | 1.0 - 1.99 | 2.0+ | Model compatibility |
| joblib | 1.1 - 1.99 | 2.0+ | AIWAF tested range |
- ✅ **Provides upgrade commands**

**Example Output:**
```
🔍 Checking project dependencies...

📊 Summary: 5 packages checked
   ✅ Up to date: 2
   ⚠️  Outdated: 2
   ❌ Not installed: 0

⚠️  OUTDATED PACKAGES:
────────────────────────────────────────
📦 pandas    1.3.5 → 2.2.2 (constraint: pandas>=1.3)
📦 numpy     1.21.0 → 1.26.4 (constraint: numpy>=1.21)

🔍 Checking package compatibility...
✅ All packages appear to be compatible!

� Planning safe package upgrades...

✅ SAFE UPGRADES PLANNED:
────────────────────────────────────────
📦 pandas              1.3.5        → 1.5.3        (Latest: 2.2.2)
   💡 Upgraded to latest safe version (AIWAF constraint: <=1.99.99)
📦 joblib              1.1.0        → 1.4.2        (Latest: 1.4.2)
   💡 Safe to upgrade to latest version

⚠️  UPGRADES BLOCKED FOR STABILITY:
────────────────────────────────────────
❌ numpy               1.21.0       ✗ 2.0.1
   🚨 NumPy 2.0+ may cause compatibility issues (max safe: 1.99.99)

🎉 Upgrade complete: 2/2 packages upgraded successfully

🧹 Clearing pip cache...
   ✅ Pip cache cleared successfully

📝 Updating requirements.txt...
   📋 Backup created: requirements.txt.backup
   📦 pandas: pandas>=1.3 → pandas>=1.5.3
   📦 joblib: joblib>=1.1 → joblib>=1.4.2
   ✅ Updated 2 packages in requirements.txt
   💾 Original backed up as: requirements.txt.backup

�💡 To update outdated packages, run:
   pip install --upgrade pandas==1.5.3 joblib
```

**Safe Upgrade System:**
- 🛡️ **AIWAF Protection**: Never breaks AIWAF functionality
- 🔍 **Compatibility Validation**: Checks package interdependencies  
- 📊 **Conservative Constraints**: Avoids known problematic versions
- 🧪 **Dry Run Mode**: Test upgrade plans before execution
- ⚠️ **Clear Blocking Reasons**: Explains why upgrades are blocked
- 📝 **Requirements.txt Updates**: Automatically updates dependency files
- 🧹 **Cache Management**: Clears pip cache after successful upgrades

**Recommended Upgrade Workflow:**

1. **Check current status:**
   ```bash
   python manage.py check_dependencies
   ```

2. **Preview safe upgrades:**
   ```bash
   python manage.py check_dependencies --upgrade --dry-run
   ```

3. **Execute safe upgrades:**
   ```bash
   python manage.py check_dependencies --upgrade --update-requirements
   ```

4. **Verify after upgrade:**
   ```bash
   python manage.py check_dependencies
   python manage.py detect_and_train  # Retrain with new packages
   ```

5. **Test your application:**
   ```bash
   python manage.py test  # Run your test suite
   ```

**Upgrade Decision Logic:**

The system uses a multi-layer decision process:

- **Layer 1**: Skip AIWAF itself (manual upgrade recommended)
- **Layer 2**: Check AIWAF compatibility constraints
- **Layer 3**: Analyze cross-package dependencies  
- **Layer 4**: Select highest safe version within constraints
- **Layer 5**: Execute with error handling and rollback capability
- **Layer 6**: Clear pip cache and update requirements.txt after success

This will ensure the IP is never blocked by AI‑WAF. You can also manage exemptions via the Django admin interface.

- **Daily Retraining**  
  Reads rotated logs, auto‑blocks 404 floods, retrains the IsolationForest, updates `model.pkl`, and evolves the keyword DB.

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
- **Database storage** with precise timestamps and response times
- **Zero configuration** - trainer automatically detects and uses model logs
- **Lightweight** - fails silently to avoid breaking your application

---

### Optional (defaults shown)

```python
AIWAF_MODEL_PATH         = BASE_DIR / "aiwaf" / "resources" / "model.pkl"
AIWAF_MIN_FORM_TIME      = 1.0        # minimum seconds between GET and POST
AIWAF_AI_CONTAMINATION   = 0.05       # AI anomaly detection sensitivity (5%)
AIWAF_RATE_WINDOW        = 10         # seconds
AIWAF_RATE_MAX           = 20         # max requests per window
AIWAF_RATE_FLOOD         = 10         # flood threshold
AIWAF_WINDOW_SECONDS     = 60         # anomaly detection window
AIWAF_FILE_EXTENSIONS    = [".php", ".asp", ".jsp"]
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

---

## 🧱 Middleware Setup

Add in **this** order to your `MIDDLEWARE` list:

```python
MIDDLEWARE = [
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

### **Dependency Upgrade Troubleshooting**

**Common Upgrade Scenarios:**

1. **NumPy 2.0 Upgrade Blocked:**
   ```bash
   # Check pandas compatibility first
   python manage.py check_dependencies --upgrade --dry-run
   
   # If pandas < 2.1, upgrade pandas first
   pip install 'pandas>=2.1,<3.0'
   
   # Then allow NumPy upgrade
   python manage.py check_dependencies --upgrade
   ```

2. **All Upgrades Blocked:**
   ```bash
   # Check what's blocking upgrades
   python manage.py check_dependencies --upgrade --dry-run
   
   # Manual override (use with caution)
   pip install --upgrade package-name
   
   # Verify AIWAF still works
   python manage.py detect_and_train
   ```

3. **Package Conflict After Upgrade:**
   ```bash
   # Check current compatibility
   python manage.py check_dependencies
   
   # Downgrade to last known good version
   pip install package-name==previous-version
   
   # Find safe upgrade path
   python manage.py check_dependencies --upgrade --dry-run
   ```

4. **AIWAF Model Issues After Upgrade:**
   ```bash
   # Regenerate model with new package versions
   python manage.py regenerate_model
   
   # Retrain with current environment
   python manage.py detect_and_train
   ```

**Emergency Rollback:**
If an upgrade breaks your system:
```bash
# Reinstall exact previous versions
pip install package-name==old-version

# Or use requirements.txt backup
pip install -r requirements.txt.backup

# Verify AIWAF functionality
python manage.py aiwaf_diagnose
```

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
| IPAndKeywordBlockMiddleware        | Blocks requests from known blacklisted IPs and Keywords         |
| RateLimitMiddleware                | Enforces burst & flood thresholds                               |
| AIAnomalyMiddleware                | ML‑driven behavior analysis + block on anomaly                  |
| HoneypotTimingMiddleware           | Detects bots via GET→POST timing analysis                       |
| UUIDTamperMiddleware               | Blocks guessed/nonexistent UUIDs across all models in an app    |

---

## 📄 License

This project is licensed under the **MIT License**. See the [LICENSE](LICENSE) file for details.

---

## 👤 Credits

**AI‑WAF** by [Aayush Gauba](https://github.com/aayushgauba)  
> “Let your firewall learn and evolve — keep your site a fortress.”
