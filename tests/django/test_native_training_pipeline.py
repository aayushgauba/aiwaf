"""CSV trainer regressions discovered by Django's management test runner."""
import csv
from contextlib import ExitStack
from pathlib import Path
from tempfile import TemporaryDirectory
from unittest import skipUnless
from unittest.mock import patch

from django.test import SimpleTestCase, override_settings
from aiwaf.core import rust_backend

try:
    import aiwaf_rust
except ImportError:
    aiwaf_rust = None


@skipUnless(aiwaf_rust and hasattr(aiwaf_rust, 'NativeTrainingBuilder'),
            'Requires the matching native CSV training extension')
class NativeTrainingPipelineTests(SimpleTestCase):
    def setUp(self):
        directory = TemporaryDirectory()
        self.addCleanup(directory.cleanup)
        self.root = Path(directory.name)
        patches = ExitStack()
        self.addCleanup(patches.close)
        patches.enter_context(patch.object(rust_backend, 'aiwaf_rust', aiwaf_rust))
        from aiwaf.django import trainer
        patches.enter_context(patch.object(trainer, '_print_geoip_summary'))
        patches.enter_context(patch.object(trainer, '_print_geoip_blocklist_summary'))
        patches.enter_context(patch.object(trainer, 'get_legitimate_keywords', return_value=set()))

    def test_streaming_csv_training_native_and_python_parity(self):
        from aiwaf.django import trainer, storage
        from aiwaf.core.runtime_storage import get_storage
        lines = [f'203.0.113.{i % 3 + 1} - - [10/Oct/2026:12:00:00 +0000] "GET /wp-content/customplugin/shell.php HTTP/1.1" 404 207 "-" "pytest" response-time=0.125\n' for i in range(4200)]
        states = []
        with patch.object(trainer, '_iter_all_logs', side_effect=lambda: iter(lines)):
            for mode in [False, True]:
                with override_settings(AIWAF_STORAGE_MODE='csv', AIWAF_DATA_DIR=str(self.root / str(mode)),
                    AIWAF_USE_RUST=True, AIWAF_RUST_CSV=mode, AIWAF_ENABLE_KEYWORD_LEARNING=True,
                    AIWAF_EXEMPT_PATHS=[], AIWAF_EXEMPT_KEYWORDS=[]):
                    trainer.train(disable_ai=True)
                    store = storage.get_keyword_store()
                    self.assertIn('customplugin', store.get_all_keywords())
                    counts = get_storage().get('keyword_counts')
                    self.assertEqual(counts['customplugin'], 4200)
                    states.append((set(storage.get_blacklist_store().get_all_blocked_ips()), counts))
        self.assertEqual(states[0], states[1])

    def test_csv_adapter_bulk_counts(self):
        from aiwaf.django.storage import get_keyword_store
        from aiwaf.core.runtime_storage import get_storage
        with override_settings(AIWAF_STORAGE_MODE='csv', AIWAF_DATA_DIR=str(self.root)):
            store = get_keyword_store()
            store.update_keywords(added=[('shelltest', 5), ('remove', 2)])
            store.update_keywords(added=[('shelltest', 3)], removed={'remove'})
            self.assertEqual(store.get_all_keywords(), ['shelltest'])
            self.assertEqual(get_storage().get('keyword_counts')['shelltest'], 8)

    def test_direct_csv_stream_and_opaque_model_fit(self):
        from aiwaf.django import trainer
        file = self.root / 'access.csv'
        with file.open('w', newline='', encoding='utf-8') as stream:
            writer = csv.writer(stream)
            writer.writerow(['timestamp', 'ip', 'path', 'status_code', 'response_time'])
            for i in range(60):
                writer.writerow(['2026-10-10T12:00:00.123456+05:30', '203.0.113.1', '/wp-content/shell.php', '404', str(i / 1000)])
        with patch.object(trainer, 'LOG_PATH', str(file)), patch.object(trainer, 'save_model_data', return_value=True) as save:
            with override_settings(AIWAF_STORAGE_MODE='csv', AIWAF_DATA_DIR=str(self.root / 'data'),
                AIWAF_USE_RUST=True, AIWAF_RUST_CSV=True, AIWAF_ENABLE_KEYWORD_LEARNING=True,
                AIWAF_RUST_FEATURE_CHUNK_SIZE=13):
                trainer.train(force_ai=True)
        save.assert_called_once()
        artifact = save.call_args.args[0]
        self.assertEqual(artifact['samples_count'], 60)
        self.assertEqual(artifact['feature_count'], 6)
        self.assertEqual(artifact['backend'], 'rust')
