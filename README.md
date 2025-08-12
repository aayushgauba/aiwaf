
# AI‑WAF

> A self‑learning, Django‑friendly Web Application Firewall  
> with rate‑limiting, anomaly detection, honeypots, UUID‑tamper protection, dynamic keyword extraction, file‑extension probing detection, exempt path awareness, and daily retraining.

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
│       └── detect_and_train.py  # `python manage.py detect_and_train`
└── LICENSE
```

---

## 🚀 Features

- **IP Blocklist**  
  Instantly blocks suspicious IPs (supports CSV fallback or Django model).

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

- **Dynamic Keyword Extraction & Cleanup**  
  - Every retrain adds top 10 keyword segments from 4xx/5xx paths  
  - **If a path is added to `AIWAF_EXEMPT_PATHS`, its keywords are automatically removed from the database**

- **File‑Extension Probing Detection**  
  Tracks repeated 404s on common extensions (e.g. `.php`, `.asp`) and blocks IPs.

- **Timing-Based Honeypot**  
  Tracks GET→POST timing patterns. Blocks IPs that:
  - POST directly without a preceding GET request
  - Submit forms faster than `AIWAF_MIN_FORM_TIME` seconds (default: 1 second)

- **UUID Tampering Protection**  
  Blocks guessed or invalid UUIDs that don’t resolve to real models.


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

All exempt paths are:
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

Clear all blacklist and exemption entries:

```bash
# Clear everything (with confirmation prompt)
python manage.py aiwaf_reset

# Clear everything without confirmation
python manage.py aiwaf_reset --confirm

# Clear only blacklist entries
python manage.py aiwaf_reset --blacklist-only

# Clear only exemption entries  
python manage.py aiwaf_reset --exemptions-only
```

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
]
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
