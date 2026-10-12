import csv
from datetime import datetime
from io import StringIO
from concurrent.futures import ThreadPoolExecutor

import pytest
from aiwaf.core import rust_backend
from aiwaf.core.logs import parse_log_line
from aiwaf.core.training_pipeline import parse_training_logs, aggregate_training_records, learn_training_keywords


@pytest.fixture
def native(monkeypatch):
    module = pytest.importorskip('aiwaf_rust')
    assert hasattr(module, 'training_parse_lines'), 'Rebuild native extension'
    monkeypatch.setattr(rust_backend, 'aiwaf_rust', module)
    monkeypatch.setenv('AIWAF_RUST_CSV', 'true')
    return module


def line(path='/wp-content/shell.php', status='404', stamp='10/Oct/2026:12:00:00 +0530', tail='response-time=0.125'):
    return f'203.0.113.1 - - [{stamp}] "GET {path} HTTP/1.1" {status} 207 "-" "pytest" {tail}\n'


def test_batch_parser_matches_single_line_parser(native, monkeypatch):
    lines = [line(), line(stamp='2026-10-10T12:00:00Z'), line(stamp='bad'), 'bad\n',
             line(path='/über/config'), line(tail=''), line(tail='response-time=1.0'),
             line(path='/known', status='200'), line(stamp='2026-10-10T12:00:00.123456-04:00')]
    expected = [record for text in lines if (record := parse_log_line(text))]
    assert parse_training_logs(lines) == expected
    monkeypatch.setenv('AIWAF_RUST_CSV', 'false')
    assert parse_training_logs(lines) == expected


def test_csv_logs_quoting_dates_and_invalid_rows(native, monkeypatch):
    output = StringIO(newline='')
    writer = csv.writer(output)
    writer.writerow(['timestamp', 'ip', 'path', 'status_code', 'response_time_ms'])
    writer.writerows([
        ['2026-10-10T12:00:00Z', '::1', '/quoted,"\npath', '404', '125'],
        ['10/Oct/2026:12:00:00', '1.1.1.1', '/known', '200', '0'],
        ['bad', '1.1.1.1', '/ignored', '404', '1'],
        ['2026-10-10T12:00:00', '1.1.1.1', '/invalid-time', '404', 'bad'],
    ])
    lines = output.getvalue().splitlines(keepends=True)
    actual = parse_training_logs(lines)
    assert len(actual) == 2
    assert actual[0]['path'] == '/quoted,"\npath'
    assert actual[0]['response_time'] == .125
    assert actual[0]['timestamp'].utcoffset().total_seconds() == 0
    monkeypatch.setenv('AIWAF_RUST_CSV', 'false')
    assert parse_training_logs(lines) == actual


def test_aggregation_parity_and_unique_route_callbacks(native, monkeypatch):
    records = parse_training_logs([line(), line('/login'), line('/known', '200')] * 100)
    calls = []
    actual = aggregate_training_records(records, lambda p: calls.append(p) or p == '/login')
    assert len(calls) == 2
    monkeypatch.setenv('AIWAF_RUST_CSV', 'false')
    expected = aggregate_training_records(records, lambda p: p == '/login')
    assert actual == expected
    assert actual[0] == {'203.0.113.1': 100}


def python_keywords(records, known, exempt, static, legitimate, top_n):
    from collections import Counter
    import re
    from aiwaf.core.training_logic import is_malicious_context
    malicious = lambda p, k, s='404': is_malicious_context(p, k, s, static, lambda p: p in known)
    tokens = Counter()
    for record in records:
        path, status = record['path'], record['status']
        if status.startswith(('4', '5')) and path not in known and path not in exempt:
            for token in re.split(r'\W+', path.lower()):
                if len(token) > 3 and token not in static and token not in legitimate and malicious(path, token, status):
                    tokens[token] += 1
    output = []
    for token, count in tokens.most_common(top_n):
        examples = [r['path'] for r in records if token in r['path'].lower()
                    and r['status'].startswith(('4', '5')) and r['path'] not in known]
        if count >= 2 and examples and any(malicious(p, token) for p in examples[:3]):
            output.append((token, count, examples[:2]))
    return output


@pytest.mark.parametrize('top_n', [-1, 0, 1, 10])
def test_keyword_parity_ties_exemptions_and_context(native, top_n):
    paths = ['/wp-content/plugins/foobar/shell.php', '/backup/customthing', '/health',
             '/exempt/config/secret', '/someinnocentthing', '/a' * 30, '/config/otherthing', '/otherthing']
    records = [dict(path=path, status=status) for status in ['200', '404', '500'] for path in paths] * 3
    known, exempt, static, legitimate = {'/health'}, {'/exempt/config/secret'}, ['.php', 'config', 'shell'], {'backup'}
    actual = learn_training_keywords(records, lambda p: p in known, lambda p: p in exempt, static, legitimate, top_n)
    assert actual == python_keywords(records, known, exempt, static, legitimate, top_n)


def test_unicode_learning_uses_python_fallback(native):
    assert learn_training_keywords([dict(path='/ü/config', status='404')], lambda p: False,
                                   lambda p: False, [], [], 10) is None


def test_keyword_batch_preserves_dates_and_concurrent_updates(native, tmp_path):
    file = tmp_path / 'keywords.csv'
    native.csv_write(str(file), ['keyword', 'added_date'], [['keep', 'old'], ['remove', 'old']], False)
    native.csv_keywords_update(str(file), 'new', ['keep', 'new'], {'remove'})
    with ThreadPoolExecutor(max_workers=5) as executor:
        list(executor.map(lambda i: native.csv_keywords_update(str(file), 'date', [f'item{i}'], set()), range(20)))
    headers, rows = native.csv_read(str(file), True)
    assert len(rows) == 22
    assert ['keep', 'old'] in rows
    assert not any(row[0] == 'remove' for row in rows)


def test_anomaly_statistics_parity_all_requests_of_selected_ips(native, monkeypatch):
    from aiwaf.core.training_pipeline import anomaly_statistics
    rows = [dict(ip=str(i % 7), kw_hits=i % 4, total_404=i % 12, burst_count=i % 20)
            for i in range(100)]
    predictions = [-1 if i == 2 else 1 for i in range(100)]
    actual = anomaly_statistics(rows, predictions)
    assert set(actual) == {'2'}
    from aiwaf.core.native_runtime import native_override
    with native_override(False):
        assert anomaly_statistics(rows, predictions) == actual
        with pytest.raises(ValueError):
            anomaly_statistics(rows, predictions[:-1])


def test_streaming_batches_do_not_materialize_whole_input(native):
    from aiwaf.core.training_pipeline import iter_training_batches
    consumed = []
    def lines():
        for i in range(10000):
            consumed.append(i)
            yield line()
    batches = iter_training_batches(lines(), batch_size=128)
    size, parsed = next(batches)
    assert size == len(parsed) == len(consumed) == 128
    batches.close()


def test_runtime_keyword_batch_concurrency(native, tmp_path):
    from aiwaf.core.runtime_storage import CSVStorage, KeywordStore
    store = KeywordStore(CSVStorage(str(tmp_path / 'runtime.csv')))
    with ThreadPoolExecutor(max_workers=5) as executor:
        list(executor.map(lambda i: store.update_keywords(added=[('same', 2), (f'item{i}', 1)]), range(20)))
    counts = store.storage.get('keyword_counts')
    assert counts['same'] == 40
    assert len(counts) == 21
    store.update_keywords(added=[('same', 3)], removed={'item0'})
    assert store.storage.get('keyword_counts')['same'] == 43
    assert 'item0' not in store.get_all_keywords()


def test_context_callbacks_keep_learning_order(native):
    from aiwaf.core.ip_keyword import evaluate_keyword_policy
    calls = []
    def context(segment):
        calls.append(segment)
        return len(calls) == 1
    result = evaluate_keyword_policy(path='/shellupload/', query_keys=[], path_exists=False,
        keyword_learning_enabled=True, static_keywords={'shell'}, dynamic_keywords=[],
        legitimate_keywords=set(), exempt_keywords=set(), safe_prefixes=[], malicious_keywords={'shell'},
        is_malicious_context=context)
    assert calls[0] == 'shellupload'
    assert result.learned_keywords == ['shellupload']
