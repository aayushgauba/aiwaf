import os
import glob
import gzip
import re
import json
import joblib

from datetime import datetime
from collections import defaultdict, Counter

import pandas as pd
from sklearn.ensemble import IsolationForest

from django.conf import settings
from django.apps import apps

# ─── CONFIG ────────────────────────────────────────────────────────────────

# Where to read your access logs (and rotated/.gz siblings)
LOG_PATH = settings.AIWAF_ACCESS_LOG

# Where we save our trained model
MODEL_PATH = os.path.join(
    os.path.dirname(__file__),
    "resources",
    "model.pkl"
)

# Static “malicious” path keywords & file extensions
MALICIOUS_KEYWORDS = [
    ".php", "xmlrpc", "wp-", ".env", ".git", ".bak",
    "conflg", "shell", "filemanager"
]
STATUS_CODES = ["200", "403", "404", "500"]

# Regex for combined log with response-time=…
_LOG_RX = re.compile(
    r'(\d+\.\d+\.\d+\.\d+).*\[(.*?)\].*"(?:GET|POST) (.*?) HTTP/.*?" '
    r'(\d{3}).*?"(.*?)" "(.*?)".*?response-time=(\d+\.\d+)'
)

# Your Django model for storing blocked IPs
BlacklistEntry = apps.get_model("aiwaf", "BlacklistEntry")


# ─── READ & PARSE LOG LINES ─────────────────────────────────────────────────

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


# ─── TRAIN ENTRYPOINT ───────────────────────────────────────────────────────

def train():
    raw = _read_all_logs()
    if not raw:
        print("❌ No log lines found – check settings.AIWAF_ACCESS_LOG")
        return

    parsed  = []
    ip_404   = defaultdict(int)
    ip_times = defaultdict(list)

    # parse + accumulate timestamps & 404 counts
    for ln in raw:
        rec = _parse(ln)
        if not rec:
            continue
        parsed.append(rec)
        ip_times[rec["ip"]].append(rec["timestamp"])
        if rec["status"] == "404":
            ip_404[rec["ip"]] += 1

    # auto-block IPs with >=6 total 404s
    newly_blocked = []
    for ip, cnt in ip_404.items():
        if cnt >= 6:
            obj, created = BlacklistEntry.objects.get_or_create(
                ip_address=ip,
                defaults={"reason": "Excessive 404s (≥6)"}
            )
            if created:
                newly_blocked.append(ip)
    if newly_blocked:
        print(f"🔒 Blocked {len(newly_blocked)} IPs for 404 flood: {newly_blocked}")

    # build feature vectors
    rows = []
    for r in parsed:
        ip         = r["ip"]
        burst      = sum(
            1 for t in ip_times[ip]
            if (r["timestamp"] - t).total_seconds() <= 10
        )
        total404   = ip_404[ip]
        kw_hits    = sum(k in r["path"].lower() for k in MALICIOUS_KEYWORDS)
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
        print("⚠️ No entries to train on.")
        return

    df = pd.DataFrame(
        rows,
        columns=[
            "path_len", "kw_hits", "resp_time",
            "status_idx", "burst_count", "total_404"
        ]
    ).fillna(0).astype(float)

    # train & save
    clf = IsolationForest(contamination=0.01, random_state=42)
    clf.fit(df.values)
    os.makedirs(os.path.dirname(MODEL_PATH), exist_ok=True)
    joblib.dump(clf, MODEL_PATH)
    print(f"✅ Model trained on {len(df)} samples → {MODEL_PATH}")

    # extract top‑10 dynamic keywords from 4xx/5xx paths
    tokens = Counter()
    for r in parsed:
        if r["status"].startswith(("4", "5")):
            segs = re.split(r"\W+", r["path"].lower())
            for seg in segs:
                if len(seg) > 3 and seg not in MALICIOUS_KEYWORDS:
                    tokens[seg] += 1

    new_kw = [kw for kw, _ in tokens.most_common(10)]
    DK_FILE = os.path.join(os.path.dirname(__file__), "resources", "dynamic_keywords.json")
    try:
        existing = set(json.load(open(DK_FILE)))
    except FileNotFoundError:
        existing = set()
    updated = sorted(existing | set(new_kw))
    with open(DK_FILE, "w") as f:
        json.dump(updated, f, indent=2)

    print(f"📝 Updated dynamic keywords: {new_kw}")
