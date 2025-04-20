import os
import glob
import gzip
import re
from datetime import datetime
from collections import defaultdict, Counter

import pandas as pd
from sklearn.ensemble import IsolationForest
import joblib

from django.conf import settings
from django.apps import apps
from django.db.models import F
from django.urls import get_resolver


LOG_PATH = settings.AIWAF_ACCESS_LOG
MODEL_PATH = os.path.join(os.path.dirname(__file__), "resources", "model.pkl")

STATIC_KW = [".php", "xmlrpc", "wp-", ".env", ".git", ".bak", "conflg", "shell", "filemanager"]
STATUS_IDX = ["200", "403", "404", "500"]

_LOG_RX = re.compile(
    r'(\d+\.\d+\.\d+\.\d+).*\[(.*?)\].*"(?:GET|POST) (.*?) HTTP/.*?" '
    r'(\d{3}).*?"(.*?)" "(.*?)".*?response-time=(\d+\.\d+)'
)

BlacklistEntry = apps.get_model("aiwaf", "BlacklistEntry")
DynamicKeyword = apps.get_model("aiwaf", "DynamicKeyword")

def is_exempt_path(path):
    path = path.lower()
    exempt_paths = getattr(settings, "AIWAF_EXEMPT_PATHS", [])
    for exempt in exempt_paths:
        if path == exempt or path.startswith(exempt.rstrip("/") + "/"):
            return True
    return False

def path_exists_in_django(path):
    from django.urls import get_resolver
    from django.urls.resolvers import URLPattern, URLResolver

    path = path.split("?")[0].lstrip("/")
    try:
        get_resolver().resolve(f"/{path}")
        return True
    except:
        pass
    parts = path.split("/")
    root_resolver = get_resolver()
    for pattern in root_resolver.url_patterns:
        if isinstance(pattern, URLResolver):
            prefix = pattern.pattern.describe().strip("^/")
            if prefix and path.startswith(prefix):
                return True
    return False

def remove_exempt_keywords():
    exempt_paths = getattr(settings, "AIWAF_EXEMPT_PATHS", [])
    exempt_tokens = set()

    for path in exempt_paths:
        path = path.strip("/").lower()
        segments = re.split(r"\W+", path)
        exempt_tokens.update(seg for seg in segments if len(seg) > 3)

    if exempt_tokens:
        deleted_count, _ = DynamicKeyword.objects.filter(keyword__in=exempt_tokens).delete()
        print(f"Removed {deleted_count} dynamic keywords that are now exempt: {list(exempt_tokens)}")

def _read_all_logs():
    lines = []
    if LOG_PATH and os.path.exists(LOG_PATH):
        with open(LOG_PATH, "r", errors="ignore") as f:
            lines.extend(f.readlines())
    for path in sorted(glob.glob(f"{LOG_PATH}.*")):
        opener = gzip.open if path.endswith(".gz") else open
        try:
            with opener(path, "rt", errors="ignore") as f:
                lines.extend(f.readlines())
        except OSError:
            continue
    return lines


def _parse(line):
    m = _LOG_RX.search(line)
    if not m:
        return None
    ip, ts_str, path, status, ref, ua, rt = m.groups()
    try:
        ts = datetime.strptime(ts_str.split()[0], "%d/%b/%Y:%H:%M:%S")
    except ValueError:
        return None
    return {
        "ip": ip,
        "timestamp": ts,
        "path": path,
        "status": status,
        "ua": ua,
        "response_time": float(rt),
    }



def train():
    remove_exempt_keywords()
    raw_lines = _read_all_logs()
    if not raw_lines:
        print("No log lines found – check AIWAF_ACCESS_LOG setting.")
        return
    parsed = []
    ip_404 = defaultdict(int)
    ip_times = defaultdict(list)
    for ln in raw_lines:
        rec = _parse(ln)
        if not rec:
            continue
        parsed.append(rec)
        ip_times[rec["ip"]].append(rec["timestamp"])
        if rec["status"] == "404":
            ip_404[rec["ip"]] += 1
    blocked_404 = []
    for ip, count in ip_404.items():
        if count >= 6:
            obj, created = BlacklistEntry.objects.get_or_create(
                ip_address=ip,
                defaults={"reason": "Excessive 404s (≥6)"}
            )
            if created:
                blocked_404.append(ip)
    if blocked_404:
        print(f"Blocked {len(blocked_404)} IPs for 404 flood: {blocked_404}")

    feature_dicts = []
    for r in parsed:
        ip = r["ip"]
        burst = sum(
            1 for t in ip_times[ip]
            if (r["timestamp"] - t).total_seconds() <= 10
        )
        total404 = ip_404[ip]
        is_known_path = path_exists_in_django(r["path"])
        kw_hits = 0
        if not is_known_path and not is_exempt_path(r["path"]):
            kw_hits = sum(k in r["path"].lower() for k in STATIC_KW)
        status_idx = STATUS_IDX.index(r["status"]) if r["status"] in STATUS_IDX else -1
        feature_dicts.append({
            "ip": ip,
            "path_len": len(r["path"]),
            "kw_hits": kw_hits,
            "resp_time": r["response_time"],
            "status_idx": status_idx,
            "burst_count": burst,
            "total_404": total404,
        })

    if not feature_dicts:
        print("⚠️ Nothing to train on – no valid log entries.")
        return
    df = pd.DataFrame(feature_dicts)
    feature_cols = [c for c in df.columns if c != "ip"]
    X = df[feature_cols].astype(float).values
    model = IsolationForest(contamination=0.01, random_state=42)
    model.fit(X)
    os.makedirs(os.path.dirname(MODEL_PATH), exist_ok=True)
    joblib.dump(model, MODEL_PATH)
    print(f"Model trained on {len(X)} samples → {MODEL_PATH}")
    preds = model.predict(X)
    anomalous_ips = set(df.loc[preds == -1, 'ip'])
    blocked_anom = []
    for ip in anomalous_ips:
        obj, created = BlacklistEntry.objects.get_or_create(
            ip_address=ip,
            defaults={"reason": "Anomalous behavior"}
        )
        if created:
            blocked_anom.append(ip)
    if blocked_anom:
        print(f"🚫 Blocked {len(blocked_anom)} anomalous IPs: {blocked_anom}")
    tokens = Counter()
    for r in parsed:
        if r["status"].startswith(("4", "5")) and not path_exists_in_django(r["path"]):
            for seg in re.split(r"\W+", r["path"].lower()):
                if len(seg) > 3 and seg not in STATIC_KW:
                    tokens[seg] += 1

    top_tokens = tokens.most_common(10)
    for kw, cnt in top_tokens:
        obj, _ = DynamicKeyword.objects.get_or_create(keyword=kw)
        DynamicKeyword.objects.filter(pk=obj.pk).update(count=F("count") + cnt)

    print(f" DynamicKeyword DB updated with top tokens: {[kw for kw, _ in top_tokens]}")



if __name__ == "__main__":
    train()