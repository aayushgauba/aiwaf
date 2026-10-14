"""Upgrade the configured Django AIWAF blocklist backend."""

from django.conf import settings
from django.core.management.base import BaseCommand, CommandError
from django.db import connection


class Command(BaseCommand):
    help = "Detect and upgrade the configured AIWAF blocklist backend"

    def handle(self, *args, **options):
        mode = str(getattr(settings, "AIWAF_STORAGE_MODE", "models") or "models").lower()
        if mode == "csv":
            from aiwaf.core.blocklist_migration import migrate_runtime_storage
            from aiwaf.django.storage import _ensure_runtime_csv_backend
            from aiwaf.core.runtime_storage import get_storage

            data_dir = _ensure_runtime_csv_backend()
            total, changed = migrate_runtime_storage(get_storage())
            self.stdout.write(self.style.SUCCESS(
                f"CSV runtime blocklist upgraded: {changed}/{total} legacy entries updated ({data_dir})"
            ))
            return

        if mode not in {"models", "database", "db", "orm"}:
            raise CommandError(f"Unsupported AIWAF_STORAGE_MODE: {mode}")

        from aiwaf.django.models import BlocklistEntry

        table = BlocklistEntry._meta.db_table
        existing_columns = {
            column.name
            for column in connection.introspection.get_table_description(
                connection.cursor(), table
            )
        }
        required = {
            "reputation_reason", "reasons", "score", "offenses", "blocked_at",
            "expires_at", "duration", "permanent",
        }
        missing = sorted(required - existing_columns)
        if missing:
            raise CommandError(
                "The Django blocklist table is missing columns: "
                + ", ".join(missing)
                + ". Run `python manage.py makemigrations aiwaf` and "
                  "`python manage.py migrate aiwaf`, then rerun this command."
            )

        changed = BlocklistEntry.objects.filter(
            reputation_reason="",
            blocked_at__isnull=True,
        ).update(
            reputation_reason="legacy_blacklist",
            reasons=["legacy_blacklist"],
            score=100,
            offenses=1,
            permanent=True,
        )
        self.stdout.write(self.style.SUCCESS(
            f"Django ORM blocklist upgraded: {changed} legacy entries updated"
        ))
