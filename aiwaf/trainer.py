import os
import glob
import gzip
import re
import joblib

from datetime import datetime
from collections import defaultdict, Counter

import pandas as pd
from sklearn.ensemble import IsolationForest

from django.conf import settings
from django.apps import apps
from django.db.models import F
from .utils import is_exempt_path
from .storage import get_blacklist_store, get_exemption_store, get_keyword_store
from .blacklist_manager import BlacklistManager

# ─────────── Configuration ───────────
LOG_PATH   = getattr(settings, 'AIWAF_ACCESS_LOG', None)
MODEL_PATH = os.path.join(os.path.dirname(__file__), "resources", "model.pkl")

STATIC_KW  = [".php", "xmlrpc", "wp-", ".env", ".git", ".bak", "conflg", "shell", "filemanager"]
STATUS_IDX = ["200", "403", "404", "500"]

_LOG_RX = re.compile(
    r'(\d+\.\d+\.\d+\.\d+).*\[(.*?)\].*"(?:GET|POST) (.*?) HTTP/.*?" '
    r'(\d{3}).*?"(.*?)" "(.*?)".*?response-time=(\d+\.\d+)'
)


def path_exists_in_django(path: str) -> bool:
    from django.urls import get_resolver
    from django.urls.resolvers import URLResolver

    candidate = path.split("?")[0].lstrip("/")
    try:
        get_resolver().resolve(f"/{candidate}")
        return True
    except:
        pass

    root = get_resolver()
    for p in root.url_patterns:
        if isinstance(p, URLResolver):
            prefix = p.pattern.describe().strip("^/")
            if prefix and candidate.startswith(prefix):
                return True
    return False


def remove_exempt_keywords() -> None:
    """Remove exempt keywords from dynamic keyword storage"""
    keyword_store = get_keyword_store()
    exempt_tokens = set()
    
    # Extract tokens from exempt paths
    for path in getattr(settings, "AIWAF_EXEMPT_PATHS", []):
        for seg in re.split(r"\W+", path.strip("/").lower()):
            if len(seg) > 3:
                exempt_tokens.add(seg)
    
    # Add explicit exempt keywords from settings
    explicit_exempt = getattr(settings, "AIWAF_EXEMPT_KEYWORDS", [])
    exempt_tokens.update(explicit_exempt)
    
    # Add legitimate path keywords to prevent them from being learned as suspicious
    allowed_path_keywords = getattr(settings, "AIWAF_ALLOWED_PATH_KEYWORDS", [])
    exempt_tokens.update(allowed_path_keywords)
    
    # Remove exempt tokens from keyword storage
    for token in exempt_tokens:
        keyword_store.remove_keyword(token)
    
    if exempt_tokens:
        print(f"🧹 Removed {len(exempt_tokens)} exempt keywords from learning: {list(exempt_tokens)[:10]}")


def get_legitimate_keywords() -> set:
    """Get all legitimate keywords that shouldn't be learned as suspicious"""
    legitimate = set()
    
    # Common legitimate path segments
    default_legitimate = {
        "profile", "user", "users", "account", "accounts", "settings", "dashboard", 
        "home", "about", "contact", "help", "search", "list", "lists",
        "view", "views", "edit", "create", "update", "delete", "detail", "details",
        "api", "auth", "login", "logout", "register", "signup", "signin",
        "reset", "confirm", "activate", "verify", "page", "pages",
        "category", "categories", "tag", "tags", "post", "posts",
        "article", "articles", "blog", "blogs", "news", "item", "items",
        "admin", "administration", "manage", "manager", "control", "panel",
        "config", "configuration", "option", "options", "preference", "preferences"
    }
    legitimate.update(default_legitimate)
    
    # Add from Django settings
    allowed_path_keywords = getattr(settings, "AIWAF_ALLOWED_PATH_KEYWORDS", [])
    legitimate.update(allowed_path_keywords)
    
    # Add exempt keywords
    exempt_keywords = getattr(settings, "AIWAF_EXEMPT_KEYWORDS", [])
    legitimate.update(exempt_keywords)
    
    return legitimate


def _read_all_logs() -> list[str]:
    lines = []
    
    # First try to read from main access log files
    if LOG_PATH and os.path.exists(LOG_PATH):
        with open(LOG_PATH, "r", errors="ignore") as f:
            lines.extend(f.readlines())
        for p in sorted(glob.glob(f"{LOG_PATH}.*")):
            opener = gzip.open if p.endswith(".gz") else open
            try:
                with opener(p, "rt", errors="ignore") as f:
                    lines.extend(f.readlines())
            except OSError:
                continue
    
    # If no log files found, fall back to RequestLog model data
    if not lines:
        lines = _get_logs_from_model()
    
    return lines


def _get_logs_from_model() -> list[str]:
    """Get log data from RequestLog model when log files are not available"""
    try:
        # Import here to avoid circular imports
        from .models import RequestLog
        from datetime import datetime, timedelta
        
        # Get logs from the last 30 days
        cutoff_date = datetime.now() - timedelta(days=30)
        request_logs = RequestLog.objects.filter(timestamp__gte=cutoff_date).order_by('timestamp')
        
        log_lines = []
        for log in request_logs:
            # Convert RequestLog to Apache-style log format that _parse() expects
            # Format: IP - - [timestamp] "METHOD path HTTP/1.1" status content_length "referer" "user_agent" response-time=X.X
            timestamp_str = log.timestamp.strftime("%d/%b/%Y:%H:%M:%S %z")
            log_line = (
                f'{log.ip_address} - - [{timestamp_str}] '
                f'"{log.method} {log.path} HTTP/1.1" {log.status_code} '
                f'{log.content_length} "{log.referer}" "{log.user_agent}" '
                f'response-time={log.response_time}\n'
            )
            log_lines.append(log_line)
        
        print(f"Loaded {len(log_lines)} log entries from RequestLog model")
        return log_lines
        
    except Exception as e:
        print(f"Warning: Could not load logs from RequestLog model: {e}")
        return []


def _parse(line: str) -> dict | None:
    m = _LOG_RX.search(line)
    if not m:
        return None
    ip, ts_str, path, status, *_ , rt = m.groups()
    try:
        ts = datetime.strptime(ts_str.split()[0], "%d/%b/%Y:%H:%M:%S")
    except ValueError:
        return None
    return {
        "ip":            ip,
        "timestamp":     ts,
        "path":          path,
        "status":        status,
        "response_time": float(rt),
    }


def train() -> None:
    """Enhanced training with improved keyword filtering and exemption handling"""
    print("🚀 Starting AIWAF enhanced training...")
    
    # Remove exempt keywords first
    remove_exempt_keywords()
    
    # Remove any IPs in IPExemption from the blacklist using BlacklistManager
    exemption_store = get_exemption_store()
    
    exempted_ips = [entry['ip_address'] for entry in exemption_store.get_all()]
    if exempted_ips:
        print(f"🛡️  Found {len(exempted_ips)} exempted IPs - clearing from blacklist")
        for ip in exempted_ips:
            BlacklistManager.unblock(ip)
    
    raw_lines = _read_all_logs()
    if not raw_lines:
        print("No log lines found – check AIWAF_ACCESS_LOG setting.")
        return

    parsed = []
    ip_404   = defaultdict(int)
    ip_404_login = defaultdict(int)  # Track 404s on login paths separately
    ip_times = defaultdict(list)

    for line in raw_lines:
        rec = _parse(line)
        if not rec:
            continue
        parsed.append(rec)
        ip_times[rec["ip"]].append(rec["timestamp"])
        if rec["status"] == "404":
            if is_exempt_path(rec["path"]):
                ip_404_login[rec["ip"]] += 1  # Login path 404s
            else:
                ip_404[rec["ip"]] += 1  # Non-login path 404s

    # 3. Optional immediate 404‐flood blocking (only for non-login paths)
    for ip, count in ip_404.items():
        if count >= 6:
            # Only block if they have significant non-login 404s
            login_404s = ip_404_login.get(ip, 0)
            total_404s = count + login_404s
            
            # Don't block if majority of 404s are on login paths
            if count > login_404s:  # More non-login 404s than login 404s
                BlacklistManager.block(ip, f"Excessive 404s (≥6 non-login, {count}/{total_404s})")

    feature_dicts = []
    for r in parsed:
        ip = r["ip"]
        burst = sum(
            1 for t in ip_times[ip]
            if (r["timestamp"] - t).total_seconds() <= 10
        )
        total404   = ip_404[ip]
        known_path = path_exists_in_django(r["path"])
        kw_hits    = 0
        if not known_path and not is_exempt_path(r["path"]):
            kw_hits = sum(k in r["path"].lower() for k in STATIC_KW)

        status_idx = STATUS_IDX.index(r["status"]) if r["status"] in STATUS_IDX else -1

        feature_dicts.append({
            "ip":           ip,
            "path_len":     len(r["path"]),
            "kw_hits":      kw_hits,
            "resp_time":    r["response_time"],
            "status_idx":   status_idx,
            "burst_count":  burst,
            "total_404":    total404,
        })

    if not feature_dicts:
        print("⚠️ Nothing to train on – no valid log entries.")
        return

    df = pd.DataFrame(feature_dicts)
    feature_cols = [c for c in df.columns if c != "ip"]
    X = df[feature_cols].astype(float).values
    model = IsolationForest(
        contamination=getattr(settings, "AIWAF_AI_CONTAMINATION", 0.05), 
        random_state=42
    )
    
    # Suppress sklearn warnings during training
    import warnings
    with warnings.catch_warnings():
        warnings.filterwarnings("ignore", category=UserWarning, module="sklearn")
        model.fit(X)

    os.makedirs(os.path.dirname(MODEL_PATH), exist_ok=True)
    
    # Save model with version metadata
    import sklearn
    from django.utils import timezone as django_timezone
    model_data = {
        'model': model,
        'sklearn_version': sklearn.__version__,
        'created_at': str(django_timezone.now()),
        'feature_count': len(feature_cols),
        'samples_count': len(X)
    }
    joblib.dump(model_data, MODEL_PATH)
    print(f"✅ Model trained on {len(X)} samples → {MODEL_PATH}")
    print(f"📦 Created with scikit-learn v{sklearn.__version__}")
    
    # Check for anomalies and intelligently decide which IPs to block
    preds = model.predict(X)
    anomalous_ips = set(df.loc[preds == -1, "ip"])
    
    if anomalous_ips:
        print(f"⚠️  Detected {len(anomalous_ips)} potentially anomalous IPs during training")
        
        exemption_store = get_exemption_store()
        blacklist_store = get_blacklist_store()
        blocked_count = 0
        
        for ip in anomalous_ips:
            # Skip if IP is exempted
            if exemption_store.is_exempted(ip):
                continue
            
            # Get this IP's behavior from the data
            ip_data = df[df["ip"] == ip]
            
            # Criteria to determine if this is likely a legitimate user vs threat:
            avg_kw_hits = ip_data["kw_hits"].mean()
            max_404s = ip_data["total_404"].max()
            avg_burst = ip_data["burst_count"].mean()
            total_requests = len(ip_data)
            
            # Don't block if it looks like legitimate behavior:
            if (
                avg_kw_hits < 2 and           # Not hitting many malicious keywords
                max_404s < 10 and            # Not excessive 404s
                avg_burst < 15 and           # Not excessive burst activity
                total_requests < 100         # Not excessive total requests
            ):
                print(f"   - {ip}: Anomalous but looks legitimate (kw:{avg_kw_hits:.1f}, 404s:{max_404s}, burst:{avg_burst:.1f}) - NOT blocking")
                continue
            
            # Block if it shows clear signs of malicious behavior
            BlacklistManager.block(ip, f"AI anomaly + suspicious patterns (kw:{avg_kw_hits:.1f}, 404s:{max_404s}, burst:{avg_burst:.1f})")
            blocked_count += 1
            print(f"   - {ip}: Blocked for suspicious behavior (kw:{avg_kw_hits:.1f}, 404s:{max_404s}, burst:{avg_burst:.1f})")
        
        print(f"   → Blocked {blocked_count}/{len(anomalous_ips)} anomalous IPs (others looked legitimate)")

    tokens = Counter()
    legitimate_keywords = get_legitimate_keywords()
    
    print(f"🔍 Learning keywords from {len(parsed)} parsed requests...")
    
    for r in parsed:
        # Only learn from suspicious requests (errors on non-existent paths)
        if (r["status"].startswith(("4", "5")) and 
            not path_exists_in_django(r["path"]) and 
            not is_exempt_path(r["path"])):
            
            for seg in re.split(r"\W+", r["path"].lower()):
                if (len(seg) > 3 and 
                    seg not in STATIC_KW and 
                    seg not in legitimate_keywords):  # Don't learn legitimate keywords
                    tokens[seg] += 1

    keyword_store = get_keyword_store()
    top_tokens = tokens.most_common(getattr(settings, "AIWAF_DYNAMIC_TOP_N", 10))
    
    # Additional filtering: only add keywords that appear suspicious enough
    filtered_tokens = []
    for kw, cnt in top_tokens:
        # Don't add keywords that might be legitimate
        if (cnt >= 2 and  # Must appear at least twice
            len(kw) >= 4 and  # Must be at least 4 characters
            kw not in legitimate_keywords):  # Not in legitimate set
            filtered_tokens.append((kw, cnt))
            keyword_store.add_keyword(kw, cnt)
    
    if filtered_tokens:
        print(f"📝 Added {len(filtered_tokens)} suspicious keywords: {[kw for kw, _ in filtered_tokens]}")
    else:
        print("✅ No new suspicious keywords learned (good sign!)")
    
    print(f"🎯 Dynamic keyword learning complete. Excluded {len(legitimate_keywords)} legitimate keywords.")
    
    # Training summary
    print("\n" + "="*60)
    print("🎉 AIWAF ENHANCED TRAINING COMPLETE")
    print("="*60)
    print(f"📊 Training Data: {len(parsed)} log entries processed")
    print(f"🤖 AI Model: Trained with {len(feature_cols)} features")
    print(f"🚫 Blocked IPs: {blocked_count if 'blocked_count' in locals() else 0} suspicious IPs blocked")
    print(f"🔑 Keywords: {len(filtered_tokens)} new suspicious keywords learned")
    print(f"🛡️  Exemptions: {len(exempted_ips)} IPs protected from blocking")
    print(f"✅ Enhanced protection now active with context-aware filtering!")
    print("="*60)
