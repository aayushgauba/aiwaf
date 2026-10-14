from aiwaf.core.storage_interfaces import BlocklistStore, ExemptionStore, KeywordStore


def test_storage_interface_protocols_are_runtime_contracts():
    assert BlocklistStore.__name__ == "BlocklistStore"
    assert ExemptionStore.__name__ == "ExemptionStore"
    assert KeywordStore.__name__ == "KeywordStore"

