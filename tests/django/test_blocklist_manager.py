from django.test import TestCase
from aiwaf.django.blocklist_manager import BlocklistManager
from aiwaf.django.storage import ModelBlocklistStore


class TestBlocklistManager(TestCase):
    def test_all_blocked_and_unblock_round_trip(self):
        ModelBlocklistStore.add_ip("203.0.113.90", "test")
        self.assertIn("203.0.113.90", BlocklistManager.all_blocked())
        BlocklistManager.unblock("203.0.113.90")
        self.assertNotIn("203.0.113.90", BlocklistManager.all_blocked())
