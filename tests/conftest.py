import pytest
import os
from pathlib import Path


def _is_installed_site_package(path: Path) -> bool:
    parts = {p.lower() for p in path.parts}
    return "site-packages" in parts or "dist-packages" in parts


def _assert_aiwaf_from_installed_package():
    if os.getenv("AIWAF_REQUIRE_INSTALLED_PACKAGE", "").lower() not in {"1", "true", "yes"}:
        return

    import aiwaf

    aiwaf_path = Path(aiwaf.__file__).resolve()
    repo_root = Path(__file__).resolve().parents[1]
    if repo_root in aiwaf_path.parents and not _is_installed_site_package(aiwaf_path):
        raise RuntimeError(
            "AIWAF_REQUIRE_INSTALLED_PACKAGE is set, but tests are importing aiwaf "
            f"from source tree: {aiwaf_path}"
        )


def _assert_aiwaf_rust_from_installed_package():
    try:
        import aiwaf_rust
    except Exception as exc:
        raise RuntimeError(
            "aiwaf-rust package is required for this test run, but module "
            "'aiwaf_rust' is not importable"
        ) from exc

    module_file = getattr(aiwaf_rust, "__file__", None)
    if not module_file:
        raise RuntimeError(
            "aiwaf-rust package is required for this test run, but "
            "aiwaf_rust.__file__ is missing"
        )

    rust_path = Path(module_file).resolve()
    repo_root = Path(__file__).resolve().parents[1]
    if repo_root in rust_path.parents and not _is_installed_site_package(rust_path):
        raise RuntimeError(
            "aiwaf-rust must come from installed package, but tests are importing "
            f"module aiwaf_rust from source tree: {rust_path}"
        )


def _rust_available():
    try:
        import aiwaf_rust  # noqa: F401
        return True
    except Exception:
        return False


def pytest_configure(config):
    _assert_aiwaf_from_installed_package()
    _assert_aiwaf_rust_from_installed_package()
    config.addinivalue_line(
        "markers",
        "requires_rust: requires installed aiwaf-rust package (module aiwaf_rust)",
    )


def pytest_runtest_setup(item):
    if "requires_rust" in item.keywords and not _rust_available():
        raise RuntimeError(
            "aiwaf-rust package (module aiwaf_rust) is required for requires_rust tests"
        )
