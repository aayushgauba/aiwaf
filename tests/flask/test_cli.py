#!/usr/bin/env python3
"""
Test AIWAF CLI functionality
"""

import tempfile
import os
import sys
from pathlib import Path
import json

# Add repo root to path
repo_root = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(repo_root))

def test_cli_functionality():
    """Test basic CLI operations."""
    print(" Testing AIWAF CLI functionality...")
    
    try:
        from aiwaf.flask.cli import AIWAFManager
        
        # Create temporary directory for testing
        with tempfile.TemporaryDirectory() as temp_dir:
            print(f" Using temporary directory: {temp_dir}")
            
            # Initialize manager with temp directory
            manager = AIWAFManager(temp_dir)
            
            # Test adding to allowlist
            print("\n Testing allowlist operations...")
            result = manager.add_to_allowlist("192.168.1.100")
            assert result, "Failed to add IP to allowlist"
            
            allowlist = manager.list_allowlist()
            assert "192.168.1.100" in allowlist, "IP not found in allowlist"
            print(f" Allowlist: {allowlist}")
            
            # Test adding to blocklist
            print("\n Testing blocklist operations...")
            result = manager.add_to_blocklist("10.0.0.5", "Test IP")
            assert result, "Failed to add IP to blocklist"
            
            blocklist = manager.list_blocklist()
            assert "10.0.0.5" in blocklist, "IP not found in blocklist"
            print(f" Blocklist: {list(blocklist.keys())}")
            
            # Test adding keywords
            print("\n Testing keyword operations...")
            result = manager.add_keyword("test-attack")
            assert result, "Failed to add keyword"
            
            keywords = manager.list_keywords()
            assert "test-attack" in keywords, "Keyword not found in list"
            print(f" Keywords: {keywords}")

            # Test geo blocked countries
            print("\n Testing geo blocked countries...")
            result = manager.add_geo_blocked_country("us")
            assert result, "Failed to add geo blocked country"
            
            countries = manager.list_geo_blocked_countries()
            assert "US" in countries, "Country not found in geo blocked list"
            print(f" Geo blocked countries: {countries}")
            
            result = manager.remove_geo_blocked_country("US")
            assert result, "Failed to remove geo blocked country"
            
            countries_after = manager.list_geo_blocked_countries()
            assert "US" not in countries_after, "Country still in geo blocked list after removal"
            
            # Test statistics
            print("\n Testing statistics...")
            manager.show_stats()
            
            # Test export/import
            print("\n Testing export/import...")
            export_file = os.path.join(temp_dir, "test_export.json")
            result = manager.export_config(export_file)
            assert result, "Failed to export configuration"
            assert os.path.exists(export_file), "Export file not created"
            
            # Test removal
            print("\n Testing removal operations...")
            result = manager.remove_from_allowlist("192.168.1.100")
            assert result, "Failed to remove IP from allowlist"
            
            allowlist_after = manager.list_allowlist()
            assert "192.168.1.100" not in allowlist_after, "IP still in allowlist after removal"
            print(f" Allowlist after removal: {allowlist_after}")
            
            print("\n All CLI tests passed!")
            assert True
            
    except Exception as e:
        print(f" CLI test failed: {e}")
        import traceback
        traceback.print_exc()
        raise AssertionError("CLI functionality test failed") from e

def test_console_script():
    """Test the console script entry point."""
    print("\n Testing console script...")
    from aiwaf.flask.cli import main
    assert callable(main)


def test_cli_geo_command(monkeypatch, tmp_path):
    """Test CLI geo blocked countries command."""
    from aiwaf.flask.cli import main

    monkeypatch.setenv("AIWAF_DATA_DIR", str(tmp_path))

    monkeypatch.setattr(sys, "argv", ["aiwaf_console.py", "geo", "list"])
    main()

    monkeypatch.setattr(sys, "argv", ["aiwaf_console.py", "geo", "add", "US"])
    main()

    monkeypatch.setattr(sys, "argv", ["aiwaf_console.py", "geo", "list"])
    main()

    monkeypatch.setattr(sys, "argv", ["aiwaf_console.py", "geo", "remove", "US"])
    main()


def test_cli_geoip_summary(monkeypatch, tmp_path, capsys):
    from aiwaf.flask.cli import AIWAFManager
    from aiwaf.flask import trainer as trainer_mod
    import aiwaf.flask.geoip as geoip_mod

    manager = AIWAFManager(str(tmp_path))

    monkeypatch.setattr(trainer_mod._trainer, "_read_all_logs", lambda: ["line1", "line2"])
    monkeypatch.setattr(
        trainer_mod._trainer,
        "_parse",
        lambda line: {"ip": "1.1.1.1"} if line == "line1" else {"ip": "2.2.2.2"},
    )
    monkeypatch.setattr(
        geoip_mod,
        "lookup_country_name",
        lambda ip, **kwargs: "United States" if ip == "1.1.1.1" else None,
    )

    manager.geoip_traffic_summary(log_dir=str(tmp_path), top=10, limit=0)

    out = capsys.readouterr().out
    assert "GeoIP traffic summary" in out
    assert "United States: 1" in out
    assert "UNKNOWN: 1" in out


def test_cli_exempt_path_command(monkeypatch, tmp_path):
    from aiwaf.flask.cli import main

    monkeypatch.setenv("AIWAF_DATA_DIR", str(tmp_path))

    monkeypatch.setattr(sys, "argv", ["aiwaf_console.py", "exempt-path", "list"])
    main()

    monkeypatch.setattr(sys, "argv", ["aiwaf_console.py", "exempt-path", "add", "/health", "--reason", "Health check"])
    main()

    monkeypatch.setattr(sys, "argv", ["aiwaf_console.py", "exempt-path", "list"])
    main()

    monkeypatch.setattr(sys, "argv", ["aiwaf_console.py", "exempt-path", "remove", "/health"])
    main()


def test_blocklist_legacy_and_import_operations(tmp_path):
    from aiwaf.flask.cli import AIWAFManager

    manager = AIWAFManager(str(tmp_path))
    manager.add_to_blocklist("203.0.113.50", "test")
    assert manager.remove_from_blocklist("203.0.113.50")
    assert not manager.remove_from_blocklist("missing")
    manager.storage["rewrite_blocklist"](
        {"203.0.113.51": {"reason": "old", "reputation_reason": "legacy_blacklist", "reasons": ["legacy_blacklist"]}}
    )
    assert manager.legacy_blocklist()
    manager.show_legacy_blocklist()
    assert manager.migrate_blocklist() == 1
    assert manager.convert_legacy_blocklist(3600) == 1
    manager.storage["rewrite_blocklist"](
        {"203.0.113.52": {"reason": "old", "reputation_reason": "legacy_blacklist", "reasons": ["legacy_blacklist"]}}
    )
    assert manager.convert_legacy_blocklist(clear=True) == 1
    assert manager.clear_blocklist()

    source = tmp_path / "import.json"
    source.write_text(json.dumps({"allowlist": ["203.0.113.53"], "blocklist": {}, "keywords": ["admin"]}), encoding="utf-8")
    assert manager.import_config(str(source))


def test_training_diagnostics_app_loader_and_duration_dispatch(tmp_path, monkeypatch):
    from types import ModuleType
    from flask import Flask
    from aiwaf.flask import cli as cli_module
    from aiwaf.flask import trainer

    manager = cli_module.AIWAFManager(str(tmp_path))
    calls = []
    monkeypatch.setattr(trainer, "train_from_logs", lambda app, disable_ai=False: calls.append(disable_ai))
    assert manager.train_model(log_dir=str(tmp_path), disable_ai=True, verbose=True)
    assert calls == [True]
    monkeypatch.setattr(trainer, "get_default_model_path", lambda: str(tmp_path / "missing.json"))
    assert manager.model_diagnostics(info=True) is False

    module = ModuleType("sample_flask_app")
    module.app = Flask("sample")
    monkeypatch.setitem(sys.modules, module.__name__, module)
    assert cli_module._load_flask_app("sample_flask_app:app") is module.app

    monkeypatch.setenv("AIWAF_DATA_DIR", str(tmp_path))
    monkeypatch.setattr(sys, "argv", ["aiwaf", "blocklist", "convert-legacy", "--duration", "1h"])
    cli_module.main()

if __name__ == '__main__':
    print(" AIWAF CLI Test Suite")
    print("=" * 50)
    
    success = True
    
    # Test CLI functionality
    if not test_cli_functionality():
        success = False
    
    # Test console script
    if not test_console_script():
        success = False
    
    if success:
        print("\n All tests passed! CLI is ready to use.")
        print("\nUsage examples:")
        print("  python aiwaf_console.py list all")
        print("  python aiwaf_console.py add allowlist 192.168.1.10")
        print("  python aiwaf_console.py add blocklist 10.0.0.1 --reason 'Suspicious activity'")
        print("  python aiwaf_console.py stats")
    else:
        print("\n Some tests failed. Please check the errors above.")
        sys.exit(1)
