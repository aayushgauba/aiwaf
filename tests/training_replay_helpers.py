import csv
from datetime import datetime, timedelta


def write_logs(path, count):
    with path.open('w', newline='', encoding='utf-8') as file:
        writer = csv.writer(file)
        writer.writerow(['timestamp', 'ip', 'path', 'status_code', 'response_time_ms'])
        for i in range(count):
            writer.writerow([(datetime(2026, 10, 10) + timedelta(seconds=i)).isoformat(),
                             '203.0.113.1', '/missing.php', '404', '10'])
