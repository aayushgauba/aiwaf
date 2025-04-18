from django.core.management.base import BaseCommand
from aiwaf.trainer import train

class Command(BaseCommand):
    help = "Run AI‑WAF detect & retrain"

    def handle(self, *args, **options):
        train()
        self.stdout.write(self.style.SUCCESS("Done."))

