from django.core.management import call_command
from django.test import TestCase, override_settings
from aiwaf.django.models import BlocklistEntry


class TestMigrateBlocklist(TestCase):
    @override_settings(AIWAF_STORAGE_MODE="models")
    def test_orm_migration_marks_legacy_rows(self):
        row = BlocklistEntry.objects.create(ip_address="203.0.113.80", reason="old")
        call_command("aiwaf_migrate_blocklist")
        row.refresh_from_db()
        self.assertEqual(row.reputation_reason, "legacy_blacklist")
