import sys
from types import ModuleType, SimpleNamespace

import pytest

from aiwaf.fast import cli


def test_load_fastapi_app_supports_instance_and_factory(monkeypatch):
    module = ModuleType("sample_fast_app")
    app = SimpleNamespace(routes=[])
    module.app = app
    module.create_app = lambda: app
    monkeypatch.setitem(sys.modules, module.__name__, module)
    assert cli._load_fastapi_app("sample_fast_app:app") is app
    assert cli._load_fastapi_app("sample_fast_app:create_app") is app
    with pytest.raises(ValueError):
        cli._load_fastapi_app("invalid")
    with pytest.raises(ValueError):
        cli._load_fastapi_app("sample_fast_app:missing")


def test_init_and_migrate_commands(tmp_path, monkeypatch, capsys):
    app = SimpleNamespace(routes=[])
    monkeypatch.setattr(cli, "_load_fastapi_app", lambda _path: app)
    monkeypatch.setattr(
        "aiwaf.fast.path_manifest.generate_fastapi_manifest",
        lambda *_args: {"framework": "fastapi", "routes": {"/": {}}, "context_hash": "abc"},
    )
    cli._init(["--app", "sample:app", "--output", str(tmp_path / "paths.json")])
    assert "Routes: 1" in capsys.readouterr().out

    cli._migrate_blocklist(["--backend", "memory"])
    assert "blocklist upgraded" in capsys.readouterr().out


def test_main_dispatches_all_modes(monkeypatch):
    calls = []
    monkeypatch.setattr(cli, "_init", lambda args: calls.append(("init", args)))
    monkeypatch.setattr(cli, "_migrate_blocklist", lambda args: calls.append(("migrate", args)))
    monkeypatch.setattr(cli, "_flask_cli_main", lambda: calls.append(("fallback", [])))
    monkeypatch.setattr(sys, "argv", ["aiwaf", "init", "--app", "x:y"])
    cli.main()
    monkeypatch.setattr(sys, "argv", ["aiwaf", "blocklist", "migrate"])
    cli.main()
    monkeypatch.setattr(sys, "argv", ["aiwaf", "status"])
    cli.main()
    assert [item[0] for item in calls] == ["init", "migrate", "fallback"]
