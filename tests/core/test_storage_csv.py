from aiwaf.core.storage_csv import safe_csv_operation


def test_storage_csv_module_contract(tmp_path):
    assert safe_csv_operation(lambda: "ok") == "ok"


def test_writer_locks_before_truncating_and_flushes_before_unlock(monkeypatch, tmp_path):
    from types import SimpleNamespace
    from aiwaf.core import storage_csv
    path = tmp_path/'locked.csv'
    path.write_text('original')
    events = []

    def flock(descriptor, operation):
        events.append(operation)
        if operation == 1:
            assert path.read_text() == 'original'
        elif operation == 3:
            assert path.read_text() == 'replacement'

    monkeypatch.setattr(storage_csv, 'FCNTL_AVAILABLE', True)
    monkeypatch.setattr(storage_csv, 'fcntl', SimpleNamespace(
        flock=flock, LOCK_EX=1, LOCK_SH=2, LOCK_UN=3), raising=False)
    with storage_csv.file_lock(path, 'w') as output:
        output.write('replacement')
    assert events == [1, 3]
