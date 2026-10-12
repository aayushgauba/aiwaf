from __future__ import annotations

from pathlib import Path


REPO_ROOT = Path(__file__).resolve().parents[2]


def _read(path: str) -> str:
    return (REPO_ROOT / path).read_text(encoding="utf-8")


def test_pyproject_uses_setuptools_not_maturin():
    content = _read("pyproject.toml")
    assert 'build-backend = "setuptools.build_meta"' in content
    assert "maturin" not in content
    assert "Cargo.toml" not in content
    assert "Cargo.lock" not in content


def test_rust_extra_defined_in_pyproject():
    content = _read("pyproject.toml")
    assert "rust = [" in content
    assert '"aiwaf-rust>=0.2.2"' in content


def test_rust_extra_defined_in_setup():
    content = _read("setup.py")
    assert '"rust": [' in content
    assert '"aiwaf-rust>=0.2.2"' in content


def test_manifest_has_no_local_rust_sources():
    content = _read("MANIFEST.in")
    assert "Cargo.toml" not in content
    assert "Cargo.lock" not in content
    assert "recursive-include src *.rs" not in content
