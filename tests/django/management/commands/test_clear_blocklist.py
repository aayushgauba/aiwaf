from django.core.management import call_command
from django.test import TestCase
from aiwaf.django.storage import ModelBlocklistStore


class TestClearBlocklist(TestCase):
    def test_confirmed_clear(self):
        ModelBlocklistStore.add_ip("203.0.113.42", "test")
        call_command("clear_blocklist", confirm=True)
        self.assertEqual(ModelBlocklistStore.get_all_blocked_ips(), [])
