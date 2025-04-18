# AI‑WAF

> A self-learning, Django-friendly Web Application Firewall  
> with rate-limiting, anomaly detection, honeypots, UUID-tamper protection, and daily retraining.

---

## Package Structure

```
aiwaf/
├── __init__.py
├── blacklist_manager.py
├── middleware.py
├── trainer.py                   # exposes detect_and_train()
├── utils.py
├── template_tags/
│   └── aiwaf_tags.py
├── resources/
│   └── model.pkl                # pre-trained base model
├── management/
│   └── commands/
│       └── detect_and_train.py  # python manage.py detect_and_train
└── LICENSE
```

---

## Features

- **IP Blocklist**  
  Automatically blocks suspicious IPs; optionally backed by CSV or Django model.

- **Rate Limiting**  
  Sliding window logic blocks IPs exceeding a threshold of requests per second.

- **AI Anomaly Detection**  
  IsolationForest trained on real logs with features like:
  - Path length
  - Keyword hits
  - Response time
  - Status code index
  - Burst count
  - Total 404s

- **Honeypot Field**  
  Hidden form field that bots are likely to fill — if triggered, the IP is blocked.

- **UUID Tampering Protection**  
  Detects if someone is probing by injecting random/nonexistent UUIDs into URLs.

- **Daily Retraining**  
  A single command retrains your model every day based on your logs.

---

## Installation

Install locally or from PyPI:

```bash
pip install aiwaf
```

Or for local dev:

```bash
git clone https://github.com/aayushgauba/aiwaf.git
cd aiwaf
pip install -e .
```

---

## ⚙️ Configuration (`settings.py`)

```python
INSTALLED_APPS += [
    "aiwaf",
]

# Required
AIWAF_ACCESS_LOG = "/var/log/nginx/access.log"

# Optional (defaults included)
AIWAF_MODEL_PATH = BASE_DIR / "aiwaf" / "resources" / "model.pkl"
AIWAF_MALICIOUS_KEYWORDS = [".php", "xmlrpc", "wp-", ".env", ".git", ".bak", "conflg", "shell", "filemanager"]
AIWAF_STATUS_CODES = ["200", "403", "404", "500"]
AIWAF_HONEYPOT_FIELD = "hp_field"
```

---

## Middleware Setup

Add to `MIDDLEWARE` in order:

```python
MIDDLEWARE = [
    "aiwaf.middleware.IPBlockMiddleware",
    "aiwaf.middleware.RateLimitMiddleware",
    "aiwaf.middleware.AIAnomalyMiddleware",
    "aiwaf.middleware.HoneypotMiddleware",
    "aiwaf.middleware.UUIDTamperMiddleware",
    ...
]
```

---

## Honeypot Field (in template)

```html
{% load aiwaf_tags %}

<form method="post">
  {% csrf_token %}
  {% honeypot_field %}
  <!-- other fields -->
</form>
```

The hidden field will be `<input type="hidden" name="hp_field">`.  
If it’s ever filled → IP gets blocked.

---

##  Run Detection + Training

```bash
python manage.py detect_and_train
```

What it does:

- Reads logs (supports `.gz` and rotated logs).
- Detects excessive 404s (≥6) → instant block.
- Builds feature vectors from logs.
- Trains IsolationForest and saves `model.pkl`.

Schedule it to run daily via `cron`, `Celery beat`, or systemd timer.

---

## How It Works (Simplified)

| Middleware             | Functionality                                                |
|------------------------|--------------------------------------------------------------|
| IPBlockMiddleware      | Blocks requests from known blacklisted IPs                   |
| RateLimitMiddleware    | Blocks flooders (>20/10s) and blacklists them (>10/10s)      |
| AIAnomalyMiddleware    | Uses ML to detect suspicious behavior in request patterns    |
| HoneypotMiddleware     | Detects bots filling hidden inputs in forms                  |
| UUIDTamperMiddleware   | Detects guessing/probing by checking invalid UUID access     |

---

## Development Roadmap

- [ ] Add CSV blocklist fallback
- [ ] Admin dashboard integration
- [ ] Auto-pruning of old block entries
- [ ] Real-time log streaming compatibility
- [ ] Docker/Helm deployment guide

---

##  License

This project is licensed under the **MIT License** — see `LICENSE` for details.

---

## Credits

**AIWAF** by [Aayush Gauba](https://github.com/aayushgauba)  
> "Let your firewall learn and evolve with your logs. Make your site a fortress."
