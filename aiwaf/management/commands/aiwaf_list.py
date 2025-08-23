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
    if not seconds: return items
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
    help = "Lister les données AIWAF (IPs bloquées, exemptions, mots-clés dynamiques)."

    def add_arguments(self, parser):
        grp = parser.add_mutually_exclusive_group()
        grp.add_argument("--ips", action="store_true", help="Lister les IPs bloquées (défaut).")
        grp.add_argument("--exemptions", action="store_true", help="Lister les IPs exemptées.")
        grp.add_argument("--keywords", action="store_true", help="Lister les mots-clés dynamiques.")
        grp.add_argument("--all", action="store_true", help="Tout lister.")
        parser.add_argument("--format", choices=["table", "json"], default="table")
        parser.add_argument("--limit", type=int, default=100)
        parser.add_argument("--order", choices=["newest", "oldest"], default="newest")
        parser.add_argument("--since", type=int, help="Fenêtre en secondes (ex: 86400 = 24h).")

    def handle(self, *args, **o):
        if not any([o["exemptions"], o["keywords"], o["all"]]):  # défaut = ips
            o["ips"] = True
        payload = {}

        if o["all"] or o["ips"]:
            data = get_blacklist_store().get_all()
            data = _filter_since(data, o.get("since"))
            data = _sort(data, o["order"])[:o["limit"]]
            payload["ips"] = data

        if o["all"] or o["exemptions"]:
            data = get_exemption_store().get_all()
            data = _filter_since(data, o.get("since"))
            data = _sort(data, o["order"])[:o["limit"]]
            payload["exemptions"] = data

        if o["all"] or o["keywords"]:
            kws = get_keyword_store().get_top_keywords(o["limit"])
            payload["keywords"] = [{"keyword": k} for k in kws]

        if o["format"] == "json":
            def _default(v):
                try: return v.isoformat()
                except Exception: return str(v)
            self.stdout.write(json.dumps(payload, ensure_ascii=False, indent=2, default=_default))
        else:
            if "ips" in payload:
                print("\n== IPs bloquées ==")
                rows = [[r.get("ip_address",""), r.get("reason",""), r.get("created_at","")]
                        for r in payload["ips"]]
                _print_table(rows, ["ip_address", "reason", "created_at"])
            if "exemptions" in payload:
                print("\n== Exemptions ==")
                rows = [[r.get("ip_address",""), r.get("reason",""), r.get("created_at","")]
                        for r in payload["exemptions"]]
                _print_table(rows, ["ip_address", "reason", "created_at"])
            if "keywords" in payload:
                print("\n== Mots-clés dynamiques ==")
                rows = [[r["keyword"]] for r in payload["keywords"]]
                _print_table(rows, ["keyword"])
