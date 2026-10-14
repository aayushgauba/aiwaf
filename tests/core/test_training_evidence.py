from datetime import datetime, timedelta
from concurrent.futures import ThreadPoolExecutor
import time
import pytest
from aiwaf.core.training_evidence import TrainingEvidence, fresh_anomaly_statistics


def records(count=6, offset=0):
    return [dict(ip='203.0.113.1', timestamp=datetime(2026, 10, 10) + timedelta(seconds=i),
                 path='/missing.php', status='404') for i in range(offset, offset + count)]


def test_native_receipts_survive_restart_rotation_and_unblocking(tmp_path):
    first = TrainingEvidence(tmp_path)
    old = records()
    assert first.fresh(old) == old
    calls = []
    assert first.block(old[0]['ip'], lambda: calls.append('first'))
    assert not first.block(old[0]['ip'], lambda: calls.append('duplicate reason'))
    first.close()
    second = TrainingEvidence(tmp_path)
    try:
        assert second.fresh(list(reversed(old)) + old) == []
        assert not second.block(old[0]['ip'], lambda: calls.append('replay'))
        new = records(offset=6)
        assert second.fresh(old + new) == new
        assert second.block(old[0]['ip'], lambda: calls.append('fresh'))
    finally:
        second.close()
    assert calls == ['first', 'fresh']


def test_failed_or_exempt_block_does_not_consume_evidence(tmp_path):
    first = TrainingEvidence(tmp_path)
    try:
        first.fresh(records())
        assert not first.block('203.0.113.1', lambda: False)
        with pytest.raises(RuntimeError, match='failed'):
            first.block('203.0.113.1', lambda: (_ for _ in ()).throw(RuntimeError('failed')))
    finally:
        first.close()
    second = TrainingEvidence(tmp_path)
    try:
        assert len(second.fresh(records())) == 6
    finally:
        second.close()


def test_native_lock_serializes_trainers_and_refreshes_state(tmp_path):
    first = TrainingEvidence(tmp_path)
    first.fresh(records())
    with ThreadPoolExecutor(max_workers=1) as pool:
        future = pool.submit(TrainingEvidence, tmp_path)
        time.sleep(.2)
        assert not future.done()
        first.block('203.0.113.1', lambda: None)
        first.close()
        second = future.result(timeout=5)
        try:
            assert second.fresh(records()) == []
        finally:
            second.close()


def test_corrupt_state_fails_closed(tmp_path):
    (tmp_path / 'training_evidence.json').write_text('{broken', encoding='utf-8')
    with pytest.raises(OSError):
        TrainingEvidence(tmp_path)


def test_fresh_anomaly_statistics_does_not_score_consumed_history():
    class Forest:
        def predict(self, values):
            assert values == [[0, 1]]
            return [-1]
    features = [dict(ip='203.0.113.1', kw_hits=0, total_404=1, burst_count=1)]
    stats = fresh_anomaly_statistics(Forest(), ['kw_hits', 'total_404'], features)
    assert stats['203.0.113.1'][1] == 1
    assert fresh_anomaly_statistics(Forest(), [], []) == {}
