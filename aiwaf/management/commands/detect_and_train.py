from django.core.management.base import BaseCommand
from aiwaf.trainer import train

class Command(BaseCommand):
    help = "Run AI‑WAF detect & retrain"

    def add_arguments(self, parser):
        parser.add_argument(
            '--disable-ai',
            action='store_true',
            help='Disable AI model training, only perform keyword learning'
        )

    def handle(self, *args, **options):
        disable_ai = options.get('disable_ai', False)
        
        if disable_ai:
            self.stdout.write(self.style.WARNING("AI model training disabled - keyword learning only"))
        
        train(disable_ai=disable_ai)
        self.stdout.write(self.style.SUCCESS("Done."))

