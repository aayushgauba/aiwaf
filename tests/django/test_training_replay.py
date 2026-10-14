from pathlib import Path
from tempfile import TemporaryDirectory
from unittest.mock import patch
from django.test import SimpleTestCase, override_settings
from aiwaf.django import trainer
from tests.training_replay_helpers import write_logs


class TrainingReplayTests(SimpleTestCase):
    def test_training_uses_only_fresh_404_evidence(self):
        with TemporaryDirectory() as directory:
            root = Path(directory)
            file = root / 'access.log'
            write_logs(file, 60)
            with override_settings(AIWAF_STORAGE_MODE='csv', AIWAF_DATA_DIR=str(root / 'data'),
                                   AIWAF_ACCESS_LOG=str(file), AIWAF_EXEMPT_PATHS=[],
                                   AIWAF_ENABLE_KEYWORD_LEARNING=False), \
                    patch.object(trainer, 'LOG_PATH', str(file)), \
                    patch.object(trainer, 'MIN_TRAIN_LOGS', 50), \
                    patch.object(trainer, 'get_legitimate_keywords', return_value=set()), \
                    patch.object(trainer, '_print_geoip_blocklist_summary'), \
                    patch.object(trainer.BlacklistManager, 'block') as block:
                trainer.train(disable_ai=True)
                self.assertEqual(block.call_count, 1)
                trainer.train(disable_ai=True)
                self.assertEqual(block.call_count, 1)
                write_logs(file, 65)
                trainer.train(disable_ai=True)
                self.assertEqual(block.call_count, 1)
                write_logs(file, 66)
                trainer.train(disable_ai=True)
                self.assertEqual(block.call_count, 2)
