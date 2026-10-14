from aiwaf.core.blocklist import should_unblock_ip


def test_should_unblock_ip_obeys_feature_and_exemption_policy():
    assert should_unblock_ip(True, lambda _ip: False, "203.0.113.1")
    assert not should_unblock_ip(False, None, "203.0.113.1")
    assert not should_unblock_ip(True, lambda _ip: True, "203.0.113.1")
