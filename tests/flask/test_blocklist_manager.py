def test_unblock_delegates_when_enabled(monkeypatch):
    from aiwaf.flask import blocklist_manager

    calls = []
    monkeypatch.setattr(blocklist_manager, "is_ip_allowlisted", lambda _ip: False)
    monkeypatch.setattr(blocklist_manager, "remove_ip_blocklist", lambda ip: calls.append(ip))
    blocklist_manager.BlocklistManager.unblock("203.0.113.120")
    assert calls == ["203.0.113.120"]
