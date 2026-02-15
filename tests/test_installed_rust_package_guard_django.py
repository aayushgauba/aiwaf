from pathlib import Path

from django.test import SimpleTestCase


def _is_installed_site_package(path: Path) -> bool:
    parts = {p.lower() for p in path.parts}
    return "site-packages" in parts or "dist-packages" in parts


class InstalledRustPackageGuardTests(SimpleTestCase):
    def test_aiwaf_rust_import_can_be_forced_to_installed_package(self):
        import aiwaf_rust

        rust_path = Path(aiwaf_rust.__file__).resolve()
        repo_root = Path(__file__).resolve().parents[1]
        self.assertFalse(
            repo_root in rust_path.parents and not _is_installed_site_package(rust_path),
            (
                "Expected installed aiwaf-rust package (module aiwaf_rust), "
                f"got source tree import: {rust_path}"
            ),
        )
