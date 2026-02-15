from pathlib import Path
import unittest


ROOT = Path(__file__).resolve().parents[1]


class PackagingRustOptionalTests(unittest.TestCase):
    def test_pyproject_uses_setuptools_backend(self):
        pyproject = (ROOT / "pyproject.toml").read_text(encoding="utf-8")
        self.assertIn('build-backend = "setuptools.build_meta"', pyproject)
        self.assertIn('requires = ["setuptools>=68", "wheel"]', pyproject)
        self.assertNotIn('build-backend = "maturin"', pyproject)

    def test_pyproject_rust_extra_points_to_aiwaf_rust(self):
        pyproject = (ROOT / "pyproject.toml").read_text(encoding="utf-8")
        self.assertIn("[project.optional-dependencies]", pyproject)
        self.assertIn("rust = [", pyproject)
        self.assertIn('"aiwaf-rust>=0.1.0"', pyproject)
        self.assertNotIn('"maturin>=1.6,<2.0"', pyproject)

    def test_setup_rust_extra_points_to_aiwaf_rust(self):
        setup_py = (ROOT / "setup.py").read_text(encoding="utf-8")
        self.assertIn("extras_require={", setup_py)
        self.assertIn('"rust": [', setup_py)
        self.assertIn('"aiwaf-rust>=0.1.0"', setup_py)
        self.assertNotIn('"maturin>=1.6,<2.0"', setup_py)

    def test_docs_explain_rust_extra_install(self):
        readme = (ROOT / "README.md").read_text(encoding="utf-8")
        installation = (ROOT / "INSTALLATION.md").read_text(encoding="utf-8")

        self.assertIn('pip install aiwaf', readme)
        self.assertIn('pip install "aiwaf[rust]"', readme)
        self.assertIn("aiwaf-rust", readme)
        self.assertNotIn("maturin develop -m Cargo.toml", readme)
        self.assertIn('pip install aiwaf', installation)
        self.assertIn('pip install "aiwaf[rust]"', installation)
        self.assertIn("aiwaf-rust", installation)
        self.assertNotIn("maturin develop -m Cargo.toml", installation)


if __name__ == "__main__":
    unittest.main()
