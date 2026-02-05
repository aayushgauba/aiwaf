import pytest


def _rust_available():
    try:
        import aiwaf_rust  # noqa: F401
        return True
    except Exception:
        return False


def pytest_configure(config):
    config.addinivalue_line(
        "markers",
        "requires_rust: requires the aiwaf_rust extension module",
    )


def pytest_runtest_setup(item):
    if "requires_rust" in item.keywords and not _rust_available():
        pytest.skip("aiwaf_rust extension not available")
