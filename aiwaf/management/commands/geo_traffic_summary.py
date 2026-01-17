from collections import Counter

from django.core.management.base import BaseCommand

from aiwaf.geoip import lookup_country_name
from aiwaf.trainer import _read_all_logs, _parse


class Command(BaseCommand):
    help = "Summarize request traffic by country using the GeoIP database"

    def add_arguments(self, parser):
        parser.add_argument(
            "--top",
            type=int,
            default=10,
            help="Number of top countries to display (default: 10)",
        )
        parser.add_argument(
            "--limit",
            type=int,
            default=0,
            help="Limit number of log lines processed (default: 0, no limit)",
        )

    def handle(self, *args, **options):
        top_n = max(1, int(options["top"]))
        limit = max(0, int(options["limit"]))

        lines = _read_all_logs()
        if not lines:
            self.stdout.write("No log lines found – check AIWAF_ACCESS_LOG setting.")
            return

        ip_counts = Counter()
        processed = 0

        for line in lines:
            rec = _parse(line)
            if not rec:
                continue
            ip_counts[rec["ip"]] += 1
            processed += 1
            if limit and processed >= limit:
                break

        if not ip_counts:
            self.stdout.write("No valid log entries to process.")
            return

        country_counts = Counter()
        unknown = 0

        for ip, count in ip_counts.items():
            name = lookup_country_name(ip, cache_prefix="aiwaf:geo:summary:", cache_seconds=3600)
            if name:
                country_counts[name] += count
            else:
                unknown += count

        self.stdout.write(f"GeoIP traffic summary (top {top_n}):")
        for code, count in country_counts.most_common(top_n):
            self.stdout.write(f"  - {code}: {count}")
        if unknown:
            self.stdout.write(f"  - UNKNOWN: {unknown}")
