"""Python adapter for Rust-owned offline enforcement receipts."""
from contextvars import ContextVar
from functools import wraps
from . import rust_backend

_current = ContextVar('aiwaf_training_evidence')


class TrainingEvidenceError(RuntimeError):
    """A receipt failure must stop training enforcement, not enable replay."""


def current_evidence():
    return _current.get()


class TrainingEvidence:
    def __init__(self, directory):
        native = getattr(rust_backend.aiwaf_rust, 'TrainingEvidence', None)
        if native is None:
            raise TrainingEvidenceError('Training requires aiwaf-rust>=0.2.5 with TrainingEvidence; upgrade the native package')
        self.native = native(str(directory))
        self.had_history = self.native.had_history

    def fresh(self, records):
        fields = []
        for record in records:
            stamp = record['timestamp']
            if hasattr(stamp, 'isoformat'):
                stamp = stamp.replace(tzinfo=None).isoformat()
            fields.append((record['ip'], str(stamp), record['path'], str(record['status'])))
        return [records[index] for index in self.native.fresh_indices(fields)]

    def block(self, ip, action):
        if not self.native.can_block(ip) or action() is False:
            return False
        try:
            self.native.commit(ip)
        except Exception as error:
            raise TrainingEvidenceError('Cannot persist training evidence; stop and repair the state directory') from error
        return True

    def close(self):
        self.native.close()


def guard_training(directory):
    def decorate(function):
        @wraps(function)
        def guarded(*args, **kwargs):
            evidence = TrainingEvidence(directory(*args, **kwargs))
            token = _current.set(evidence)
            try:
                return function(*args, **kwargs)
            finally:
                _current.reset(token)
                evidence.close()
        return guarded
    return decorate


def fresh_anomaly_statistics(model, columns, features):
    """Score fresh enforcement features with a model fitted on the full history."""
    from .training_pipeline import anomaly_statistics
    if not features:
        return {}
    if hasattr(features, 'to_dicts'):
        features = features.to_dicts()
    matrix = [[float(row.get(key, float('nan'))) for key in columns] for row in features]
    return anomaly_statistics(features, model.predict(matrix))
