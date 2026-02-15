from pathlib import Path
import unittest


ROOT = Path(__file__).resolve().parents[1]


class PackagingRustOptionalTests(unittest.TestCase):
    def test_pyproject_uses_setuptools_backend(self):
        pyproject = (ROOT / "pyproject.toml").read_text(encoding="utf-8")
        self.assertIn('build-backend = "setuptools.build_meta"', pyproject)
        self.assertIn('requires = ["setuptools>=68", "wheel"]', pyproject)
        self.assertNotIn('build-backend = "maturin"', pyproject)

    def test_pyproject_rust_is_optional_extra(self):
        pyproject = (ROOT / "pyproject.toml").read_text(encoding="utf-8")
        self.assertIn("[project.optional-dependencies]", pyproject)
        self.assertIn("rust = [", pyproject)
        self.assertIn('"maturin>=1.6,<2.0"', pyproject)

    def test_setup_declares_rust_extra(self):
        setup_py = (ROOT / "setup.py").read_text(encoding="utf-8")
        self.assertIn("extras_require={", setup_py)
        self.assertIn('"rust": [', setup_py)
        self.assertIn('"maturin>=1.6,<2.0"', setup_py)

    def test_docs_explain_opt_in_rust_install(self):
        readme = (ROOT / "README.md").read_text(encoding="utf-8")
        installation = (ROOT / "INSTALLATION.md").read_text(encoding="utf-8")

        self.assertIn('pip install aiwaf', readme)
        self.assertIn('pip install "aiwaf[rust]"', readme)
        self.assertIn("If a prebuilt wheel is available", readme)
        self.assertIn("Only if you are installing from source", readme)
        self.assertIn("maturin develop -m Cargo.toml", readme)
        self.assertIn('pip install aiwaf', installation)
        self.assertIn('pip install "aiwaf[rust]"', installation)
        self.assertIn("If a prebuilt wheel is available", installation)
        self.assertIn("Only if you are installing from source", installation)
        self.assertIn("maturin develop -m Cargo.toml", installation)


if __name__ == "__main__":
    unittest.main()
