import csv
from datetime import datetime, timezone
import gzip
from concurrent.futures import ThreadPoolExecutor
import pytest
from aiwaf.core import rust_backend
from aiwaf.core.training_pipeline import convert_training_fields, iter_csv_training_batches, anomaly_statistics


@pytest.fixture
def native(monkeypatch):
    module = pytest.importorskip('aiwaf_rust')
    assert hasattr(module, 'NativeTrainingBatch'), 'Rebuild native extension'
    monkeypatch.setattr(rust_backend, 'aiwaf_rust', module)
    monkeypatch.setenv('AIWAF_RUST_CSV', 'true')
    yield module
    if hasattr(module, 'csv_log_close'):
        module.csv_log_close(None)


@pytest.mark.parametrize('apache,stamps', [
    (True, ['10/Oct/2026:12:30:59 +0530', '1/Jan/2026:1:2:3', 'bad', '31/Feb/2026:12:00:00', '2026-10-10T12:00:00Z']),
    (False, ['2026-10-10T12:30:59.123456789+05:30', '2026-10-10 12:30:59Z',
             '2026-10-10T12:30:59-04:00', '2026-10-10', '2026-W41-6T12:00:00',
             '20261010T123059', '2026-10-10T12:00:00+01:02:03', '2026-10-10T12:00:00.', 'bad'])])
def test_timestamp_forms_native_python_parity(native, monkeypatch, apache, stamps):
    fields = [('1.1.1.1', stamp, '/path', '200', .1) for stamp in stamps]
    actual = convert_training_fields(fields, apache=apache, prefer_native_iso=True)
    monkeypatch.setenv('AIWAF_RUST_CSV', 'false')
    assert convert_training_fields(fields, apache=apache, prefer_native_iso=True) == actual


@pytest.mark.parametrize('compressed', [False, True])
def test_streaming_csv_quotes_gzip_and_time_units(native, tmp_path, monkeypatch, compressed):
    path = tmp_path / ('access.csv.gz' if compressed else 'access.csv')
    opener = gzip.open if compressed else open
    with opener(path, 'wt', newline='', encoding='utf-8') as file:
        writer = csv.writer(file)
        writer.writerow(['timestamp', 'ip', 'path', 'status_code', 'response_time'])
        for i in range(17):
            writer.writerow(['2026-10-10T12:00:00.123456+05:30', '::1', '/quote,"\npath', '404', '.125'])
    batches = list(iter_csv_training_batches(path, batch_size=3))
    assert [count for count, _ in batches] == [3, 3, 3, 3, 3, 2]
    assert batches[0][1][0]['response_time'] == .125
    assert batches[0][1][0]['timestamp'].microsecond == 123456
    legacy = list(iter_csv_training_batches(path, batch_size=3, legacy_csv=True))
    assert legacy[0][1][0]['timestamp'] == datetime(2026, 10, 10, 12)
    monkeypatch.setenv('AIWAF_RUST_CSV', 'false')
    assert list(iter_csv_training_batches(path, batch_size=3)) == batches


def records():
    return [dict(ip=str(i % 7), path='/wp-content/shell.php' if i % 3 else '/docs',
                 status='404' if i % 3 else '200', timestamp=datetime(2026, 1, 1, tzinfo=timezone.utc),
                 response_time=i / 1000) for i in range(100)]


def test_native_matrix_fit_and_model_state_parity(native):
    rows = records()
    args = (rows, {'/docs': False, '/wp-content/shell.php': True}, {}, ['200', '404'], ['shell', '.php'])
    native_batch = native.extract_native_training_features(*args)
    features = native.extract_raw_features(*args)
    assert native_batch.to_dicts() == features
    assert len(native_batch) == len(rows)
    columns = native_batch.feature_columns()
    matrix = [[float(row[key]) for key in columns] for row in features]
    old, new = native.IsolationForest(n_estimators=10, random_state=42), native.IsolationForest(n_estimators=10, random_state=42)
    old.fit(matrix)
    expected = anomaly_statistics(features, old.predict(matrix))
    actual = native_batch.fit_predict(new)
    assert actual == expected
    assert new.to_json() == old.to_json()


def test_native_streaming_builder_matches_existing_chunks(native):
    inputs = [dict(ip=str(i % 3), path_lower='/shell', path_len=6, timestamp=float(i),
                   response_time=.1, status_idx=1, kw_check=True, total_404=10) for i in range(100)]
    builder = native.NativeTrainingBuilder()
    state, expected = None, []
    for offset in range(0, len(inputs), 13):
        batch = inputs[offset:offset + 13]
        output = native.extract_features_batch_with_state(batch, ['shell'], state)
        expected.extend(output['features'])
        state = output['state']
        builder.add_batch(batch, ['shell'])
    assert builder.finish().to_dicts() == expected
    assert len(builder.finish()) == 0


def test_noop_policy_mutation_preserves_file_and_empty_schema(native, tmp_path):
    file = tmp_path / 'keywords.csv'
    native.csv_keywords_update(str(file), 'old', [], set())
    assert native.csv_read(str(file), True) == (['keyword', 'added_date'], [])
    native.csv_keywords_update(str(file), 'old', ['same'], set())
    stamp = file.stat().st_mtime_ns
    original = file.read_bytes()
    with ThreadPoolExecutor(max_workers=5) as executor:
        list(executor.map(lambda _: native.csv_keywords_update(str(file), 'new', ['same'], {'missing'}), range(20)))
    assert file.read_bytes() == original
    assert file.stat().st_mtime_ns == stamp


def test_combined_keyword_reads_refresh_and_learning_disabled(native, tmp_path):
    file = tmp_path / 'keywords.csv'
    native.csv_keywords_update(str(file), 'date', ['custom'], set())
    def decide(learning):
        return native.csv_keyword_apply_from_store(str(file), 'date', '/custom/', '', set(), False,
            learning, set(), set(), set(), [], set(), 10)
    assert decide(True)[0] is not None
    native.csv_keywords_update(str(file), 'date', [], {'custom'})
    assert decide(True)[0] is None
    native.csv_keywords_update(str(file), 'date', ['custom'], set())
    assert decide(False)[0] is None


def test_cached_writer_rotation_truncation_and_close(native, tmp_path):
    file = tmp_path / 'access.csv'
    native.csv_log_append(str(file), ['path'], ['/first'], False)
    file.rename(tmp_path / 'rotated.csv')
    native.csv_log_append(str(file), ['path'], ['/second'], True)
    assert native.csv_read(str(file), True) == (['path'], [['/second']])
    file.write_text('')
    native.csv_log_append(str(file), ['path'], ['/third'], False)
    assert native.csv_read(str(file), True) == (['path'], [['/third']])
    native.csv_log_close(str(file))
    file.unlink()
    native.csv_log_append(str(file), ['path'], ['/fourth'], False)
    native.csv_log_close(None)
    assert native.csv_read(str(file), True) == (['path'], [['/fourth']])
