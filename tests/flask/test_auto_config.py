from pathlib import Path

import pytest

from aiwaf.flask import auto_config


@pytest.mark.parametrize("location", ["aiwaf_data", ".aiwaf/data"])
def test_upgrade_reuses_project_csv_before_populated_user_store(tmp_path, monkeypatch, location):
    project = tmp_path / "project"
    project.mkdir()
    home = tmp_path / "home"
    user_store = home / "aiwaf_data"
    user_store.mkdir(parents=True)
    (user_store / "blacklist.csv").write_text("ip\n" + "203.0.113.9\n" * 100)
    old_store = project / location
    old_store.mkdir(parents=True)
    old_file = old_store / "blacklist.csv"
    old_file.write_text("ip,reason,added_date\n203.0.113.1,probe,2026-10-01\n")
    original = old_file.read_bytes()
    (old_store / "keywords.csv").write_text("keyword,added_date\nscanner-test,2026-10-01\n")
    monkeypatch.chdir(project)
    monkeypatch.setattr(Path, "home", classmethod(lambda cls: home))
    monkeypatch.delenv("AIWAF_DATA_DIR", raising=False)
    cfg = auto_config.AIWAFAutoConfig()

    assert cfg.auto_detect_data_directory() == str(old_store.absolute())
    assert old_file.read_bytes() == original
    assert cfg.get_config_info()["detection_method"] == "existing_project_directory"
    from aiwaf.flask.cli import get_storage_instance
    monkeypatch.setattr(auto_config, "_auto_config", cfg)
    storage = get_storage_instance()
    assert storage['data_dir']() == str(old_store.absolute())
    assert storage['read_keywords']() == {"scanner-test"}
    assert old_file.read_bytes() == original


def test_upgrade_finds_home_data_directory_and_path_exemptions_only(tmp_path, monkeypatch):
    project = tmp_path / "project"
    project.mkdir()
    old_store = tmp_path / "home" / ".aiwaf" / "data"
    old_store.mkdir(parents=True)
    (old_store / "path_exemptions.csv").write_text("path,reason,added_date\n/health,monitor,2026-10-01\n")
    monkeypatch.chdir(project)
    monkeypatch.setattr(Path, "home", classmethod(lambda cls: tmp_path / "home"))
    monkeypatch.delenv("AIWAF_DATA_DIR", raising=False)
    monkeypatch.delenv("APPDATA", raising=False)
    cfg = auto_config.AIWAFAutoConfig()

    assert cfg.auto_detect_data_directory() == str(old_store.absolute())
    assert not (old_store / "aiwaf_data").exists()


def test_explicit_new_directory_overrides_existing_project_data(tmp_path, monkeypatch):
    old_store = tmp_path / "aiwaf_data"
    old_store.mkdir()
    (old_store / "blacklist.csv").write_text("ip\n203.0.113.1\n")
    target = tmp_path / "new" / "custom-data"
    monkeypatch.chdir(tmp_path)
    monkeypatch.setenv("AIWAF_DATA_DIR", str(target))
    cfg = auto_config.AIWAFAutoConfig()

    assert cfg.auto_detect_data_directory() == str(target.absolute())
    assert target.is_dir()
    assert cfg.get_config_info()["detection_method"] == "environment_variable"


def test_auto_config_filesystem_detection_contracts(tmp_path, monkeypatch):
    cfg = auto_config.AIWAFAutoConfig()
    monkeypatch.chdir(tmp_path)
    monkeypatch.setattr(Path, "home", classmethod(lambda cls: tmp_path))

    env_data = tmp_path / "env-data"
    env_data.mkdir()
    monkeypatch.setenv("AIWAF_DATA_DIR", str(env_data))
    assert cfg.auto_detect_data_directory() == str(env_data.absolute())
    assert cfg.get_config_info()["detection_method"] == "environment_variable"

    app_file = tmp_path / "app.py"
    configured = tmp_path / "configured"
    app_file.write_text("app = Flask(__name__)\nAIWAF_DATA_DIR = 'configured'\n", encoding="utf-8")
    assert cfg._analyze_python_file_for_flask_app(app_file)
    assert cfg._find_flask_app_config()

    data = tmp_path / "aiwaf_data"
    data.mkdir()
    assert cfg._validate_aiwaf_data_dir(data)
    assert cfg._search_existing_data_directories()
    (tmp_path / "pyproject.toml").touch()
    assert cfg._detect_project_structure()
    assert cfg._can_create_directory(tmp_path / "new-dir")
    assert cfg._create_fallback_directory()


def test_auto_config_scoring_logs_and_global_helpers(tmp_path, monkeypatch):
    cfg = auto_config.AIWAFAutoConfig()
    monkeypatch.setattr(Path, "home", classmethod(lambda cls: tmp_path))
    data = tmp_path / "aiwaf_data"
    data.mkdir()
    (data / "blacklist.csv").write_text("ip\n203.0.113.1\n", encoding="utf-8")
    assert cfg._calculate_data_directory_score(data) > 0
    assert cfg._validate_aiwaf_data_dir(data)

    logs = tmp_path / "logs"
    logs.mkdir()
    (logs / "access.log").write_text("request", encoding="utf-8")
    assert cfg._validate_log_directory(logs)
    assert cfg._calculate_log_directory_score(logs) >= 60
    cfg.data_dir = str(data)
    assert cfg.auto_detect_log_directory() == str(logs.absolute())
    assert cfg.get_log_config_info()["detection_method"] == "existing_log_directory"

    monkeypatch.setenv("AIWAF_LOG_DIR", str(logs))
    assert cfg.auto_detect_log_directory() == str(logs.absolute())
    monkeypatch.delenv("AIWAF_DATA_DIR", raising=False)
    assert cfg._find_best_existing_data_directory()
    assert cfg._create_user_data_directory()
    cfg._use_package_based_data_directory()

    auto_config._auto_config = cfg
    assert auto_config.get_auto_configured_log_dir()[0]
    assert auto_config.get_auto_configured_data_dir()[0]
    auto_config.print_auto_config_info(cfg.get_config_info())
