import os
import re
import glob
import gzip
from datetime import datetime

_LOG_RX = re.compile(
    r'(\d+\.\d+\.\d+\.\d+).*\[(.*?)\].*"(GET|POST) (.*?) HTTP/.*?" (\d{3}).*?"(.*?)" "(.*?)"'
)

def get_ip(request):
    xff = request.META.get("HTTP_X_FORWARDED_FOR", "")
    if xff:
        return xff.split(",")[0].strip()
    return request.META.get("REMOTE_ADDR", "")

def read_rotated_logs(base_path):
    lines = []
    if os.path.exists(base_path):
        with open(base_path, "r", encoding="utf-8", errors="ignore") as f:
            lines.extend(f.readlines())
    for path in sorted(glob.glob(base_path + ".*")):
        opener = gzip.open if path.endswith(".gz") else open
        try:
            with opener(path, "rt", encoding="utf-8", errors="ignore") as f:
                lines.extend(f.readlines())
        except OSError:
            continue
    return lines

def parse_log_line(line):
    m = _LOG_RX.search(line)
    if not m:
        return None
    ip, ts_str, _, path, status, ref, ua = m.groups()
    try:
        ts = datetime.strptime(ts_str.split()[0], "%d/%b/%Y:%H:%M:%S")
    except ValueError:
        return None
    rt_m = re.search(r'response-time=(\d+\.\d+)', line)
    rt = float(rt_m.group(1)) if rt_m else 0.0
    return {
        "ip": ip,
        "timestamp": ts,
        "path": path,
        "status": status,
        "referer": ref,
        "user_agent": ua,
        "response_time": rt
    }