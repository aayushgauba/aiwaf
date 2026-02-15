from pathlib import Path

from django.test import SimpleTestCase


class InstalledPackageGuardTests(SimpleTestCase):
    def test_aiwaf_import_can_be_forced_to_installed_package(self):
        import aiwaf

        aiwaf_path = Path(aiwaf.__file__).resolve()
        self.assertTrue(aiwaf_path.exists())
