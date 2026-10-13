"""Wheel-level coverage: no dependency on the Python AIWAF source tree."""
import json
import csv
import pytest
import aiwaf_rust


def test_wheel_exposes_complete_csv_pipeline(tmp_path):
    engine = aiwaf_rust.NativeCSVPipeline(json.dumps({
        'data_dir':str(tmp_path), 'enabled':['ip_keyword_block', 'logging'], 'exempt_paths':[]}))
    context, status, payload = engine.begin('8.8.8.8', '/docs', 'GET', {}, b'q=union+select', b'',
        True, True, True, True, False, set(), False, 100., '2026-10-12T00:00:00+00:00')
    assert status == 403
    assert json.loads(payload)['error'] == 'sql_union_select'
    assert engine.finish(context, status, 100.1, str(len(payload)))[0] == 403
    assert engine.processed_requests == 1
    with (tmp_path / 'requests.csv').open(newline='') as file:
        assert list(csv.DictReader(file))[0]['status_code'] == '403'
    with pytest.raises(RuntimeError, match='already finalized'):
        engine.finish(context, status, 100.1, '0')


def test_wheel_memory_honeypot_is_local_and_keeps_timing_policy(tmp_path):
    config = json.dumps({'data_dir':str(tmp_path), 'enabled':['honeypot'],
                         'exempt_paths':[], 'honeypot_backend':'memory'})
    engine = aiwaf_rust.NativeCSVPipeline(config)
    other = aiwaf_rust.NativeCSVPipeline(config)
    def call(owner, method, now):
        ctx, status, _ = owner.begin('8.8.8.8', '/form', method, {}, b'', b'', True,
            True, True, True, False, set(), False, now, 'wheel-test')
        owner.finish(ctx, status or 200, now+.01, '0')
        return status
    assert call(engine, 'GET', 100.) == 0
    assert call(other, 'POST', 100.05) == 0
    assert call(engine, 'POST', 100.05) == 403
    assert not (tmp_path / 'pipeline_state.csv').exists()
