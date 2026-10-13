from pathlib import Path
import unittest


ROOT = Path(__file__).resolve().parents[2]


class PackagingRustOptionalTests(unittest.TestCase):
    def test_rust_is_a_required_runtime_dependency(self):
        pyproject = (ROOT / "pyproject.toml").read_text(encoding="utf-8")
        required = pyproject.split("dependencies = [", 1)[1].split("]", 1)[0]
        self.assertIn('"aiwaf-rust>=0.2.3"', required)
        setup_py = (ROOT / "setup.py").read_text(encoding="utf-8")
        required = setup_py.split("install_requires=[", 1)[1].split("]", 1)[0]
        self.assertIn('"aiwaf-rust>=0.2.3"', required)
    def test_pyproject_uses_setuptools_backend(self):
        pyproject = (ROOT / "pyproject.toml").read_text(encoding="utf-8")
        self.assertIn('build-backend = "setuptools.build_meta"', pyproject)
        self.assertIn('requires = ["setuptools>=77", "wheel"]', pyproject)
        self.assertNotIn('build-backend = "maturin"', pyproject)

    def test_pyproject_rust_extra_points_to_aiwaf_rust(self):
        pyproject = (ROOT / "pyproject.toml").read_text(encoding="utf-8")
        self.assertIn("[project.optional-dependencies]", pyproject)
        self.assertIn("rust = [", pyproject)
        self.assertIn('"aiwaf-rust>=0.2.3"', pyproject)
        self.assertNotIn('"maturin>=1.6,<2.0"', pyproject)

    def test_setup_rust_dependency_is_required(self):
        setup_py = (ROOT / "setup.py").read_text(encoding="utf-8")
        required = setup_py.split("install_requires=[", 1)[1].split("]", 1)[0]
        self.assertIn('"aiwaf-rust>=0.2.3"', required)
        self.assertNotIn('"maturin>=1.6,<2.0"', setup_py)

    def test_readme_explains_rust_extra_install(self):
        readme = (ROOT / "README.md").read_text(encoding="utf-8")

        self.assertIn('pip install aiwaf', readme)
        self.assertIn('pip install "aiwaf[rust]"', readme)
        self.assertIn("aiwaf-rust", readme)
        self.assertNotIn("maturin develop -m Cargo.toml", readme)


if __name__ == "__main__":
    unittest.main()
