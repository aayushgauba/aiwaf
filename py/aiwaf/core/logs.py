"""
Shared log parsing helpers.
"""

from __future__ import annotations

import glob
import gzip
import os
import re
import csv
from datetime import datetime
from aiwaf.core.storage_csv import file_lock
from aiwaf.core.native_runtime import csv_function, csv_values


def write_csv_log(csv_file: str, headers: list[str], row: dict, *, durable: bool = False) -> None:
    # Match DictWriter's rejection of extra fields before invoking a native writer.
    if row.keys() - headers:
        return
    native_log = csv_function('csv_log_append')
    if native_log is not None:
        try:
            native_log(str(csv_file), headers, csv_values([row.get(key, '') for key in headers]), durable)
        except Exception:
            pass  # Do not retry a possibly completed append and duplicate a record.
        return
    log_dir = os.path.dirname(csv_file)
    if log_dir:
        os.makedirs(log_dir, exist_ok=True)

    try:
        with file_lock(csv_file, mode="a"):
            needs_header = not os.path.exists(csv_file) or os.path.getsize(csv_file) == 0
            with open(csv_file, "a", newline="", encoding="utf-8") as f:
                writer = csv.DictWriter(f, fieldnames=headers)
                if needs_header:
                    writer.writeheader()
                writer.writerow(row)
                if durable:
                    f.flush()
                    os.fsync(f.fileno())
    except Exception:
        pass


_LOG_RX_PATTERNS = [
    # Combined log format with response time (IPv4 + IPv6)
    re.compile(
        r'(\S+).*\[(.*?)\].*"(?:GET|POST|PUT|DELETE|HEAD|OPTIONS) (.*?) HTTP/.*?" '
        r'(\d{3}).*?"(.*?)" "(.*?)".*?response-time=(\d+\.\d+)'
    ),
    # Standard combined log format (IPv4 + IPv6)
    re.compile(
        r'(\S+).*\[(.*?)\].*"(?:GET|POST|PUT|DELETE|HEAD|OPTIONS) (.*?) HTTP/.*?" '
        r'(\d{3}) (\d+) "(.*?)" "(.*?)"'
    ),
    # Common log format (IPv4 + IPv6)
    re.compile(
        r'(\S+).*\[(.*?)\].*"(?:GET|POST|PUT|DELETE|HEAD|OPTIONS) (.*?) HTTP/.*?" '
        r'(\d{3}) (\d+)'
    ),
]


def read_rotated_logs(base_path: str) -> list[str]:
    lines: list[str] = []
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


def parse_log_line(line: str) -> dict | None:
    for pattern in _LOG_RX_PATTERNS:
        m = pattern.search(line)
        if not m:
            continue
        groups = m.groups()
        ip = groups[0]
        ts_str = groups[1]
        path = groups[2]
        status = groups[3]

        rt = 0.0
        for group in groups[4:]:
            try:
                if "." in str(group):
                    rt = float(group)
                    break
            except (ValueError, TypeError):
                continue

        try:
            ts = datetime.strptime(ts_str.split()[0], "%d/%b/%Y:%H:%M:%S")
        except ValueError:
            try:
                ts = datetime.fromisoformat(ts_str.replace("Z", "+00:00"))
            except ValueError:
                continue

        return {
            "ip": ip,
            "timestamp": ts,
            "path": path,
            "status": status,
            "response_time": rt,
        }

    return None
