from django.core.management.base import BaseCommand
from django.utils import timezone
from aiwaf.storage import get_blacklist_store, get_exemption_store, get_keyword_store
from datetime import timedelta
import json

def _sort(items, order):
    reverse = (order == "newest")
    return sorted(items, key=lambda x: x.get("created_at") or timezone.make_aware(timezone.datetime.min),
                  reverse=reverse)

def _filter_since(items, seconds):
    if not seconds:
        return items
    cutoff = timezone.now() - timedelta(seconds=seconds)
    return [it for it in items if it.get("created_at") and it["created_at"] >= cutoff]

def _print_table(rows, headers):
    widths = [len(h) for h in headers]
    for r in rows:
        for i, cell in enumerate(r):
            widths[i] = max(widths[i], len(str(cell)))
    print(" | ".join(h.ljust(widths[i]) for i, h in enumerate(headers)))
    print("-+-".join("-" * w for w in widths))
    for r in rows:
        print(" | ".join(str(cell).ljust(widths[i]) for i, cell in enumerate(r)))

class Command(BaseCommand):
    help = "AIWAF list (v2): blocked IPs, exempted IPs, monitored keywords."

    def add_arguments(self, parser):
        grp = parser.add_mutually_exclusive_group()
        grp.add_argument("--ips-blocked", action="store_true", help="List blocked IPs (blacklist).")
        grp.add_argument("--ips-exempted", action="store_true", help="List exempted IPs (whitelist).")
        grp.add_argument("--keywords-monitored", action="store_true", help="List monitored dynamic keywords.")
        grp.add_argument("--all", action="store_true", help="List everything.")

        parser.add_argument("--format", choices=["table", "json"], default="table", help="Output format.")
        parser.add_argument("--limit", type=int, default=100, help="Max items to display.")
        parser.add_argument("--order", choices=["newest", "oldest"], default="newest", help="Sort order for IP entries.")
        parser.add_argument("--since", type=int, help="Time window in seconds (e.g. 86400 = last 24h) for IP entries.")
        parser.add_argument("--only-ip", action="store_true", help="For IP lists: print only the IP column.")

    def handle(self, *args, **options):
        # default: show blocked IPs if nothing specific is requested
        if not any([options["ips_blocked"], options["ips_exempted"], options["keywords_monitored"], options["all"]]):
            options["ips_blocked"] = True

        payload = {}

        if options["all"] or options["ips_blocked"]:
            data = get_blacklist_store().get_all()  # [{ip_address, reason, created_at}]
            data = _filter_since(data, options.get("since"))
            data = _sort(data, options["order"])[: options["limit"]]
            payload["ips_blocked"] = data

        if options["all"] or options["ips_exempted"]:
            data = get_exemption_store().get_all()  # [{ip_address, reason, created_at}]
            data = _filter_since(data, options.get("since"))
            data = _sort(data, options["order"])[: options["limit"]]
            payload["ips_exempted"] = data

        if options["all"] or options["keywords_monitored"]:
            kws = get_keyword_store().get_top_keywords(options["limit"])  # [str]
            payload["keywords_monitored"] = [{"keyword": k} for k in kws]

        if options["format"] == "json":
            def _default(v):
                try:
                    return v.isoformat()
                except Exception:
                    return str(v)
            self.stdout.write(json.dumps(payload, ensure_ascii=False, indent=2, default=_default))
            return

        # table output
        if "ips_blocked" in payload:
            print("\n== IPs blocked ==")
            rows = payload["ips_blocked"]
            if options["only_ip"]:
                for r in rows:
                    print(r.get("ip_address", ""))
            else:
                _print_table(
                    [[r.get("ip_address",""), r.get("reason",""), r.get("created_at","")] for r in rows],
                    ["ip_address", "reason", "created_at"],
                )

        if "ips_exempted" in payload:
            print("\n== IPs exempted ==")
            rows = payload["ips_exempted"]
            if options["only_ip"]:
                for r in rows:
                    print(r.get("ip_address", ""))
            else:
                _print_table(
                    [[r.get("ip_address",""), r.get("reason",""), r.get("created_at","")] for r in rows],
                    ["ip_address", "reason", "created_at"],
                )

        if "keywords_monitored" in payload:
            print("\n== Keywords monitored ==")
            rows = payload["keywords_monitored"]
            _print_table([[r["keyword"]] for r in rows], ["keyword"])