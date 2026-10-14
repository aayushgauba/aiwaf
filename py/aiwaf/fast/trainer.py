"""FastAPI training using shared batch preparation and the runtime storage backend."""
from collections import Counter
from pathlib import Path
import gzip
import re

from starlette.routing import Match
from aiwaf.core import rust_backend
from aiwaf.core.constants import STATUS_IDX
from aiwaf.core.defaults import DEFAULT_EXEMPT_PATHS_FLASK
from aiwaf.core.exemptions import is_path_exempt
from aiwaf.core.native_runtime import native_override, enabled
from aiwaf.core.runtime_storage import get_keyword_store, get_blocklist_store, get_exemption_store
from aiwaf.core.training_pipeline import parse_training_logs, iter_csv_training_batches, aggregate_training_records, learn_training_keywords, anomaly_statistics, python_training_features
import csv
from aiwaf.core.training_features import extract_raw_features, extract_native_batch
from aiwaf.core.training_logic import get_default_legitimate_keywords, is_malicious_context
from aiwaf.core.model_artifacts import rust_model_artifact
from aiwaf.core.model_serialization import dump_model_artifact
from aiwaf.core.training_evidence import guard_training, current_evidence, fresh_anomaly_statistics
from aiwaf.core.runtime_storage import get_storage
from aiwaf.core.storage_schema import DEFAULT_DATA_DIR


def _evidence_directory(app, **options):
    config = options.get('config') or getattr(getattr(app, 'state', None), 'aiwaf_config', None)
    storage = get_storage()
    default = getattr(storage, 'data_dir', None) or Path(getattr(storage, 'file_path', Path(DEFAULT_DATA_DIR) / 'runtime_metadata.csv')).parent
    return config.get('AIWAF_TRAINING_STATE_DIR', default) if config is not None else default

STATIC_KW = ['.php', 'xmlrpc', 'wp-', '.env', '.git', '.bak', 'config', 'shell', 'filemanager']


def path_exists(app, path):
    scope = dict(type='http', path=path.split('?', 1)[0], method='GET', root_path='', headers=[])
    def visit(routes, scope):
        for route in routes:
            match, child = route.matches(scope)
            if match == Match.NONE:
                continue
            children = getattr(route, 'routes', None)
            if children is not None:
                if visit(children, {**scope, **child}):
                    return True
            else:
                return True  # Recognized path, including routes with a different HTTP method.
        return False
    return visit(app.routes, scope)


def _read_logs(log_dir):
    root = Path(log_dir)
    files = list(dict.fromkeys([root / 'access.log', *sorted(root.glob('access.log.*')),
                               *sorted(root.glob('*access*.csv')), *sorted(root.glob('*access*.csv.gz'))]))
    records = []
    for file in files:
        if not file.is_file():
            continue
        opener = gzip.open if file.suffix == '.gz' else open
        with opener(file, 'rt', encoding='utf-8', errors='ignore', newline='') as stream:
            first = stream.readline()
        if {'timestamp', 'ip', 'path', 'status_code'} <= set(next(csv.reader([first]), [])):
            for _, batch in iter_csv_training_batches(file):
                records.extend(batch)
        else:
            with opener(file, 'rt', encoding='utf-8', errors='ignore') as stream:
                records.extend(parse_training_logs(stream.readlines()))
    return records


@guard_training(_evidence_directory)
def train_from_logs(app, *, log_dir=None, disable_ai=False, force_ai=False,
                    min_ai_logs=10000, model_path=None, config=None):
    """Train offline; storage must already be initialized by AIWAF or the caller.

    A Rust JSON model is saved only when a model path is configured. The returned
    model can also be supplied to the anomaly middleware by application code.
    """
    config = config or getattr(getattr(app, 'state', None), 'aiwaf_config', None)
    get = config.get if config is not None else lambda key, default=None: default
    use_rust = bool(get('AIWAF_USE_RUST', True) and get('AIWAF_RUST_CSV', True))
    with native_override(use_rust):
        use_rust = use_rust and enabled()
        parsed = _read_logs(log_dir or get('logging_middleware.log_dir', 'aiwaf_logs'))
        result = dict(parsed_records=len(parsed), blocked_404=0, blocked_ai=0, learned_keywords=[], model=None, model_path=None)
        if len(parsed) < 50:
            return result
        known_cache, exempt_cache = {}, {}
        configured_paths = get('AIWAF_EXEMPT_PATHS', DEFAULT_EXEMPT_PATHS_FLASK)
        def known(path):
            if path not in known_cache:
                known_cache[path] = path_exists(app, path)
            return known_cache[path]
        def exempt(path):
            if path not in exempt_cache:
                exempt_cache[path] = is_path_exempt(path, configured_paths, allow_wildcards=True, allow_prefix=True)
            return exempt_cache[path]
        errors, exempt_errors, times = aggregate_training_records(parsed, exempt)
        evidence = current_evidence()
        fresh = evidence.fresh(parsed)
        fresh_errors, fresh_exempt_errors, fresh_times = aggregate_training_records(fresh, exempt)
        blocklist, exemptions, keywords = get_blocklist_store(), get_exemption_store(), get_keyword_store()
        def block(ip, reason):
            if exemptions.is_exempted(ip):
                return False
            return evidence.block(ip, lambda: blocklist.block_ip(ip, reason))
        for ip, count in fresh_errors.items():
            exempt_count = fresh_exempt_errors.get(ip, 0)
            if count >= 6 and count > exempt_count:
                result['blocked_404'] += block(ip, f'Excessive 404s (>=6 non-login, {count}/{count + exempt_count})')
        features = extract_native_batch(parsed, errors, known, exempt, STATUS_IDX, STATIC_KW) if use_rust else None
        if features is None and use_rust:
            features = extract_raw_features(parsed, errors, known, exempt, STATUS_IDX, STATIC_KW)
        if features is None:
            features = python_training_features(parsed, errors, times, known, exempt, STATIC_KW, STATUS_IDX)
        if (not disable_ai and (force_ai or len(parsed) >= min_ai_logs) and features
                and use_rust and rust_backend.rust_isolation_forest_available()):
            native_batch = hasattr(features, 'fit_predict')
            columns = features.feature_columns() if native_batch else list(dict.fromkeys(k for row in features for k in row if k != 'ip'))
            matrix = features if native_batch else [[float(row.get(key, float('nan'))) for key in columns] for row in features]
            model = rust_backend.rust_isolation_forest_class()(contamination=get('AIWAF_AI_CONTAMINATION', .05), random_state=42)
            if native_batch:
                statistics = features.fit_predict(model)
            else:
                model.fit(matrix)
                statistics = {} if evidence.had_history else anomaly_statistics(features, model.predict(matrix))
            result['model'] = model
            if evidence.had_history:
                fresh_features = extract_raw_features(fresh, fresh_errors, known, exempt, STATUS_IDX, STATIC_KW) if use_rust and fresh else None
                if fresh_features is None:
                    fresh_features = python_training_features(fresh, fresh_errors, fresh_times, known, exempt, STATIC_KW, STATUS_IDX)
                statistics = fresh_anomaly_statistics(model, columns, fresh_features)
            for ip, (kw, errors_count, burst, count) in statistics.items():
                if (kw < 2 and errors_count < 10 and burst < 15 and count < 100) or (kw == 0 and errors_count == 0):
                    continue
                result['blocked_ai'] += block(ip, f'AI anomaly + suspicious patterns (kw:{kw:.1f}, 404s:{errors_count}, burst:{burst:.1f})')
            destination = model_path or get('ai_anomaly.model_path', None)
            if destination:
                Path(destination).parent.mkdir(parents=True, exist_ok=True)
                dump_model_artifact(rust_model_artifact(model, columns, len(matrix), 'fastapi'), destination)
                result['model_path'] = str(destination)
        if get('AIWAF_ENABLE_KEYWORD_LEARNING', True):
            legitimate = get_default_legitimate_keywords() | set(get('AIWAF_ALLOWED_PATH_KEYWORDS', [])) | set(get('AIWAF_EXEMPT_KEYWORDS', []))
            def route_tokens(routes):
                for route in routes:
                    legitimate.update(re.findall(r'[A-Za-z][A-Za-z0-9_]{2,}', str(getattr(route, 'path', '')).lower()))
                    route_tokens(getattr(route, 'routes', []) or [])
            route_tokens(app.routes)
            removed = set(get('AIWAF_EXEMPT_KEYWORDS', [])) | set(get('AIWAF_ALLOWED_PATH_KEYWORDS', []))
            for path in configured_paths:
                removed.update(s for s in re.split(r'\W+', str(path).lower()) if len(s) > 3)
            learned = learn_training_keywords(parsed, known, exempt, STATIC_KW, legitimate, int(get('AIWAF_DYNAMIC_TOP_N', 10))) if use_rust else None
            if learned is None:
                counts = Counter()
                for record in parsed:
                    path, status = record['path'], record['status']
                    if not status.startswith(('4', '5')) or known(path) or exempt(path):
                        continue
                    for token in re.split(r'\W+', path.lower()):
                        if len(token) > 3 and token not in STATIC_KW and token not in legitimate and is_malicious_context(path, token, status, STATIC_KW, known):
                            counts[token] += 1
                learned = []
                for token, count in counts.most_common(int(get('AIWAF_DYNAMIC_TOP_N', 10))):
                    examples = [r['path'] for r in parsed if token in r['path'].lower() and r['status'].startswith(('4', '5')) and not known(r['path'])]
                    if count >= 2 and any(is_malicious_context(p, token, '404', STATIC_KW, known) for p in examples[:3]):
                        learned.append((token, count, examples[:2]))
            keywords.update_keywords(added=[(key, count) for key, count, _ in learned], removed=removed)
            result['learned_keywords'] = [key for key, _, _ in learned]
        return result


# Compatibility aliases for callers using the previous terminology.
get_blacklist_store = get_blocklist_store
