from django.core.management.base import BaseCommand, CommandError
import json


class Command(BaseCommand):
    help = "Run a python-whois lookup for a domain or IP."

    def add_arguments(self, parser):
        parser.add_argument(
            "target",
            help="Domain or IP to look up (e.g. example.com or 1.2.3.4)",
        )
        parser.add_argument(
            "--format",
            choices=["json", "table"],
            default="json",
            help="Output format",
        )

    def handle(self, *args, **options):
        try:
            import whois
        except Exception:
            raise CommandError(
                "python-whois is not installed. Install it with: pip install python-whois"
            )

        target = options["target"]
        try:
            result = whois.whois(target)
        except Exception as exc:
            raise CommandError(f"Whois lookup failed for {target}: {exc}")

        data = dict(result) if hasattr(result, "keys") else {"result": result}

        if options["format"] == "json":
            self.stdout.write(json.dumps(data, ensure_ascii=False, indent=2, default=str))
            return

        # table output
        rows = []
        for key in sorted(data.keys()):
            rows.append([key, data.get(key)])

        col1 = max(len(r[0]) for r in rows) if rows else 10
        self.stdout.write("key".ljust(col1) + " | value")
        self.stdout.write("-" * col1 + "-+-" + "-" * 40)
        for key, value in rows:
            self.stdout.write(str(key).ljust(col1) + " | " + str(value))
