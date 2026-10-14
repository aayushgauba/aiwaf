from fastapi import FastAPI
from aiwaf.fast.trainer import train_from_logs
from aiwaf.core.runtime_storage import initialize_storage, get_blacklist_store
from tests.training_replay_helpers import write_logs


def test_fast_training_replay_and_fresh_threshold(tmp_path):
    logs = tmp_path / 'logs'
    logs.mkdir()
    file = logs / 'access.log'
    write_logs(file, 60)
    initialize_storage('csv', data_dir=str(tmp_path / 'data'))
    app = FastAPI()
    assert train_from_logs(app, log_dir=logs, disable_ai=True)['blocked_404'] == 1
    assert train_from_logs(app, log_dir=logs, disable_ai=True)['blocked_404'] == 0
    get_blacklist_store().unblock_ip('203.0.113.1')
    initialize_storage('csv', data_dir=str(tmp_path / 'data'))
    assert train_from_logs(app, log_dir=logs, disable_ai=True)['blocked_404'] == 0
    write_logs(file, 65)
    assert train_from_logs(app, log_dir=logs, disable_ai=True)['blocked_404'] == 0
    write_logs(file, 66)
    assert train_from_logs(app, log_dir=logs, disable_ai=True)['blocked_404'] == 1
