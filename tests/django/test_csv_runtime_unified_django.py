import csv
import json
import time
from pathlib import Path
from tempfile import TemporaryDirectory
from django.test import SimpleTestCase, override_settings


class UnifiedCSVStorageTests(SimpleTestCase):
    def test_shared_policy_files_and_legacy_migration(self):
        from aiwaf.django.storage import get_blocklist_store, get_exemption_store, get_keyword_store
        from aiwaf.core import storage_csv_impl as policy
        from aiwaf.core.runtime_storage import get_storage

        with TemporaryDirectory() as directory, override_settings(AIWAF_STORAGE_MODE='csv', AIWAF_DATA_DIR=directory):
            root = Path(directory)
            source = root / 'runtime_store.csv'
            expiry = time.time() + 600
            with source.open('w', newline='') as stream:
                writer = csv.writer(stream)
                writer.writerow(['key', 'value', 'expires_at'])
                writer.writerow(['blocked:203.0.113.8', json.dumps({'reason': 'legacy', 'expires_at': expiry}), expiry])
                writer.writerow(['keyword_counts', json.dumps({'legacy-keyword': 7}), ''])
            original = source.read_bytes()
            exemptions = get_exemption_store()
            blocks = get_blocklist_store()
            keywords = get_keyword_store()
            self.assertTrue(blocks.is_blocked('203.0.113.8'))
            self.assertEqual(policy.read_blocklist(root)['203.0.113.8']['expires_at'], expiry)
            self.assertEqual(get_storage().get('keyword_counts'), {'legacy-keyword': 7})
            exemptions.add_exemption('192.0.2.1', 'trusted')
            self.assertIn('192.0.2.1', policy.read_allowlist(root))
            blocks.block_ip('198.51.100.23', 'Django canonical block')
            self.assertIn('198.51.100.23', policy.read_blocklist(root))
            keywords.add_keyword('shared-keyword', count=2)
            self.assertIn('shared-keyword', policy.read_keywords(root))
            blocks.unblock_ip('203.0.113.8')
            self.assertFalse(get_blocklist_store().is_blocked('203.0.113.8'))
            self.assertEqual(source.read_bytes(), original)
