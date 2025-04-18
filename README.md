# AI‑WAF

> A self‑learning, Django‑friendly Web Application Firewall  
> with rate‑limiting, anomaly detection, honeypots, UUID‑tamper protection, dynamic keyword extraction, file‑extension probing detection, and daily retraining.

---

## Package Structure

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

## Features

- **IP Blocklist**  
  Instantly blocks suspicious IPs (supports CSV fallback or Django model).

- **Rate Limiting**  
  Sliding‑window blocks flooders (> `AIWAF_RATE_MAX` per `AIWAF_RATE_WINDOW`), then blacklists them.

- **AI Anomaly Detection**  
  IsolationForest on features:
  - Path length  
  - Keyword hits (static + dynamic)  
  - Response time  
  - Status‑code index  
  - Burst count  
  - Total 404s  

- **Dynamic Keyword Extraction**  
  Every retrain: top 10 most frequent “words” from 4xx/5xx paths are appended to your malicious keyword set.

- **File‑Extension Probing Detection**  
  Tracks repeated 404s on common web‑extensions (e.g. `.php`, `.asp`) and auto‑blocks after a burst.

- **Honeypot Field**  
  Hidden form field (via template tag) that bots fill → instant block.

- **UUID Tampering Protection**  
  Any `<uuid:…>` URL that doesn’t map to **any** model in its Django app gets blocked.

- **Daily Retraining**  
  Reads rotated/gzipped logs, auto‑blocks 404 floods (≥6), retrains the model, updates `model.pkl` + `dynamic_keywords.json`.

---

## Installation

```bash
# From PyPI
pip install aiwaf

# Or for local development
git clone https://github.com/aayushgauba/aiwaf.git
cd aiwaf
pip install -e .
```

---

## ⚙️ Configuration (`settings.py`)

```python
INSTALLED_APPS += ["aiwaf"]

# Required
AIWAF_ACCESS_LOG = "/var/log/nginx/access.log"

# Optional (defaults shown)
AIWAF_MODEL_PATH         = BASE_DIR / "aiwaf" / "resources" / "model.pkl"
AIWAF_HONEYPOT_FIELD     = "hp_field"
AIWAF_RATE_WINDOW        = 10         # seconds
AIWAF_RATE_MAX           = 20         # max reqs/window
AIWAF_RATE_FLOOD         = 10         # flood threshold
AIWAF_WINDOW_SECONDS     = 60         # anomaly window
AIWAF_FILE_EXTENSIONS    = [".php", ".asp", ".jsp"]  # 404‑burst tracked extensions
```

> **Note:** You no longer need to define `AIWAF_MALICIOUS_KEYWORDS` or `AIWAF_STATUS_CODES` in your settings — they’re built in and evolve dynamically.

---

## Middleware Setup

Add in **this** order to your `MIDDLEWARE` list:

```python
MIDDLEWARE = [
    "aiwaf.middleware.IPBlockMiddleware",
    "aiwaf.middleware.RateLimitMiddleware",
    "aiwaf.middleware.AIAnomalyMiddleware",
    "aiwaf.middleware.HoneypotMiddleware",
    "aiwaf.middleware.UUIDTamperMiddleware",
    # ... other middleware ...
]
```

---

## Honeypot Field (in your template)

```django
{% load aiwaf_tags %}

<form method="post">
  {% csrf_token %}
  {% honeypot_field %}
  <!-- your real fields -->
</form>
```

> Renders a hidden `<input name="hp_field" style="display:none">`.  
> Any non‑empty submission → IP blacklisted.

---

## Running Detection & Training

```bash
python manage.py detect_and_train
```

**What happens:**
1. Read access logs
2. Auto‑block IPs with ≥ 6 total 404s
3. Extract features & train IsolationForest
4. Save `model.pkl`
5. Extract top 10 dynamic keywords from 4xx/5xx

---

## How It Works

| Middleware               | Purpose                                                         |
|--------------------------|------------------------------------------------------------------|
| IPBlockMiddleware        | Blocks requests from known blacklisted IPs                      |
| RateLimitMiddleware      | Enforces burst & flood thresholds                               |
| AIAnomalyMiddleware      | ML‑driven behavior analysis + block on anomaly                  |
| HoneypotMiddleware       | Detects bots filling hidden inputs in forms                     |
| UUIDTamperMiddleware     | Blocks guessed/nonexistent UUIDs across all models in an app    |

---

## License

This project is licensed under the **MIT License**. See the [LICENSE](LICENSE) file for details.

---

## Credits

**AI‑WAF** by [Aayush Gauba](https://github.com/aayushgauba)  
> “Let your firewall learn and evolve — keep your site a fortress.”