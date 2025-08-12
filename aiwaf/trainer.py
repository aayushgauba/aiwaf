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

# ─────────── Configuration ───────────
LOG_PATH   = settings.AIWAF_ACCESS_LOG
MODEL_PATH = os.path.join(os.path.dirname(__file__), "resources", "model.pkl")

STATIC_KW  = [".php", "xmlrpc", "wp-", ".env", ".git", ".bak", "conflg", "shell", "filemanager"]
STATUS_IDX = ["200", "403", "404", "500"]

_LOG_RX = re.compile(
    r'(\d+\.\d+\.\d+\.\d+).*\[(.*?)\].*"(?:GET|POST) (.*?) HTTP/.*?" '
    r'(\d{3}).*?"(.*?)" "(.*?)".*?response-time=(\d+\.\d+)'
)


BlacklistEntry = apps.get_model("aiwaf", "BlacklistEntry")
DynamicKeyword = apps.get_model("aiwaf", "DynamicKeyword")
IPExemption = apps.get_model("aiwaf", "IPExemption")


def is_exempt_path(path: str) -> bool:
    path = path.lower()
    
    # Default login paths that should always be exempt
    default_login_paths = [
        "/admin/login/",
        "/admin/",
        "/login/",
        "/accounts/login/",
        "/auth/login/",
        "/signin/",
    ]
    
    # Check default login paths
    for login_path in default_login_paths:
        if path.startswith(login_path):
            return True
    
    # Check user-configured exempt paths
    for exempt in getattr(settings, "AIWAF_EXEMPT_PATHS", []):
        if path == exempt or path.startswith(exempt.rstrip("/") + "/"):
            return True
    return False


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
    exempt_tokens = set()
    for path in getattr(settings, "AIWAF_EXEMPT_PATHS", []):
        for seg in re.split(r"\W+", path.strip("/").lower()):
            if len(seg) > 3:
                exempt_tokens.add(seg)
    if exempt_tokens:
        DynamicKeyword.objects.filter(keyword__in=exempt_tokens).delete()


def _read_all_logs() -> list[str]:
    lines = []
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
    return lines


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
    remove_exempt_keywords()
    # Remove any IPs in IPExemption from the blacklist
    exempt_ips = set(IPExemption.objects.values_list("ip_address", flat=True))
    if exempt_ips:
        BlacklistEntry.objects.filter(ip_address__in=exempt_ips).delete()
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
                BlacklistEntry.objects.get_or_create(
                    ip_address=ip,
                    defaults={"reason": f"Excessive 404s (≥6 non-login, {count}/{total_404s})"}
                )

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
    model.fit(X)

    os.makedirs(os.path.dirname(MODEL_PATH), exist_ok=True)
    joblib.dump(model, MODEL_PATH)
    print(f"Model trained on {len(X)} samples → {MODEL_PATH}")
    preds = model.predict(X)
    anomalous_ips = set(df.loc[preds == -1, "ip"])
    for ip in anomalous_ips:
        BlacklistEntry.objects.get_or_create(
            ip_address=ip,
            defaults={"reason": "Anomalous behavior"}
        )

    tokens = Counter()
    for r in parsed:
        if (r["status"].startswith(("4", "5"))
            and not path_exists_in_django(r["path"])):
            for seg in re.split(r"\W+", r["path"].lower()):
                if len(seg) > 3 and seg not in STATIC_KW:
                    tokens[seg] += 1

    for kw, cnt in tokens.most_common(10):
        obj, _ = DynamicKeyword.objects.get_or_create(keyword=kw)
        DynamicKeyword.objects.filter(pk=obj.pk).update(count=F("count") + cnt)

    print(f"DynamicKeyword DB updated with top tokens: {[kw for kw, _ in tokens.most_common(10)]}")
