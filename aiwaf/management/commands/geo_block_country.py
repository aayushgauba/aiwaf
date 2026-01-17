from django.core.management.base import BaseCommand

from aiwaf.models import GeoBlockedCountry


class Command(BaseCommand):
    help = "Manage geo-blocked countries stored in the database"

    def add_arguments(self, parser):
        parser.add_argument("action", choices=["add", "remove", "list"])
        parser.add_argument("country", nargs="?", help="ISO country code (e.g. US)")

    def handle(self, *args, **options):
        action = options["action"]
        country = options["country"]
        blocked = list(
            GeoBlockedCountry.objects.values_list("country_code", flat=True)
        )
        blocked = [c.upper() for c in blocked if c]

        if action == "list":
            if blocked:
                self.stdout.write("Blocked countries: " + ", ".join(sorted(set(blocked))))
            else:
                self.stdout.write("Blocked countries: (none)")
            return

        if not country:
            self.stderr.write("Country code is required.")
            return

        country = country.upper()
        if action == "add":
            GeoBlockedCountry.objects.get_or_create(country_code=country)
            self.stdout.write(f"Blocked country added: {country}")
            return

        if action == "remove":
            GeoBlockedCountry.objects.filter(country_code=country).delete()
            self.stdout.write(f"Blocked country removed: {country}")
