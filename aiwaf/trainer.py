# aiwaf/trainer.py

import os
import glob
import gzip
import re
import joblib
from datetime import datetime
from collections import defaultdict
from .models import BlacklistEntry
import pandas as pd
from sklearn.ensemble import IsolationForest
from django.conf import settings
from django.apps import apps

LOG_PATH   = settings.AIWAF_ACCESS_LOG
MODEL_PATH = os.path.join(
    os.path.dirname(__file__),
    "resources",
    "model.pkl"
)
MALICIOUS_KEYWORDS = [".php", "xmlrpc", "wp-", ".env", ".git", ".bak", "conflg", "shell", "filemanager"]
STATUS_CODES       = ["200", "403", "404", "500"]
_LOG_RX = re.compile(
    r'(\d+\.\d+\.\d+\.\d+).*\[(.*?)\].*"(?:GET|POST) (.*?) HTTP/.*?" (\d{3}).*?"(.*?)" "(.*?)".*?response-time=(\d+\.\d+)'
)
BlacklistedIP = BlacklistEntry.objects.all()
def _read_all_logs():
    lines = []
    if LOG_PATH and os.path.exists(LOG_PATH):
        with open(LOG_PATH, "r", errors="ignore") as f:
            lines += f.readlines()
    for path in sorted(glob.glob(LOG_PATH + ".*")):
        opener = gzip.open if path.endswith(".gz") else open
        try:
            with opener(path, "rt", errors="ignore") as f:
                lines += f.readlines()
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
    raw = _read_all_logs()
    if not raw:
        print("No log lines found – check AIWAF_ACCESS_LOG")
        return
    parsed = []
    ip_404   = defaultdict(int)
    ip_times = defaultdict(list)
    for ln in raw:
        rec = _parse(ln)
        if not rec:
            continue
        parsed.append(rec)
        ip_times[rec["ip"]].append(rec["timestamp"])
        if rec["status"] == "404":
            ip_404[rec["ip"]] += 1
    blocked = []
    for ip, count in ip_404.items():
        if count >= 6:
            obj, created = BlacklistEntry.objects.get_or_create(
                ip_address=ip,
                defaults={"reason": "Excessive 404s (≥6)"}
            )
            if created:
                blocked.append(ip)
    if blocked:
        print(f"Auto‑blocked {len(blocked)} IPs for ≥6 404s: {', '.join(blocked)}")
    rows = []
    for r in parsed:
        ip        = r["ip"]
        burst     = sum(
            1 for t in ip_times[ip]
            if (r["timestamp"] - t).total_seconds() <= 10
        )
        total404  = ip_404[ip]
        kw_hits   = sum(k in r["path"].lower() for k in MALICIOUS_KEYWORDS)
        status_idx = STATUS_CODES.index(r["status"]) if r["status"] in STATUS_CODES else -1
        rows.append([
            len(r["path"]),
            kw_hits,
            r["response_time"],
            status_idx,
            burst,
            total404
        ])

    if not rows:
        print("No entries to train on!")
        return

    df = pd.DataFrame(
        rows,
        columns=[
            "path_len", "kw_hits", "resp_time",
            "status_idx", "burst_count", "total_404"
        ]
    ).fillna(0).astype(float)
    clf = IsolationForest(contamination=0.01, random_state=42)
    clf.fit(df.values)
    os.makedirs(os.path.dirname(MODEL_PATH), exist_ok=True)
    joblib.dump(clf, MODEL_PATH)
    print(f"Model trained on {len(df)} samples and saved to {MODEL_PATH}")

