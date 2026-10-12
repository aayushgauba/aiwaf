"""Check the installed Python/native pairing without touching application state."""
import json
from pathlib import Path
import tempfile


REQUIRED = (
    'csv_read', 'csv_write', 'csv_kv_get', 'csv_kv_update', 'csv_blacklist_check',
    'csv_runtime_block', 'csv_runtime_list_update', 'csv_policy_list_update',
    'csv_keyword_apply', 'csv_log_append', 'csv_request_exempt',
    'policy_ip_exempt', 'policy_path_exempt', 'policy_route_plan',
    'training_parse_lines', 'training_parse_csv', 'training_aggregate',
    'training_keywords', 'training_anomaly_stats', 'csv_keywords_update',
    'training_keyword_counts', 'csv_runtime_keywords_update',
    'NativeTrainingBatch', 'NativeTrainingBuilder', 'extract_native_training_features',
    'TrainingCSVReader', 'training_date_parts', 'csv_keyword_apply_from_store', 'csv_log_close',
)


def check():
    import aiwaf
    from aiwaf.core import native_runtime, rust_backend
    module = rust_backend.aiwaf_rust
    report = {'python_version': aiwaf.__version__, 'python_source': aiwaf.__file__,
        'rust_source': getattr(module, '__file__', None), 'enabled': native_runtime.enabled(),
        'missing_capabilities': [name for name in REQUIRED if not hasattr(module, name)],
        'smoke_test_passed': False}
    if report['missing_capabilities'] or not report['enabled']:
        return report
    with tempfile.TemporaryDirectory(prefix='aiwaf-preflight-') as directory:
        path = str(Path(directory) / 'runtime.csv')
        module.csv_runtime_list_update(path, 'add_ip', '203.0.113.7', 'preflight', 100.0)
        module.csv_runtime_list_update(path, 'add_country', 'US', '', 100.0)
        if json.loads(module.csv_kv_get(path, 'exemptions', 100.0))['ips'] != ['203.0.113.7']:
            raise RuntimeError('Exemption round-trip failed')
        if json.loads(module.csv_kv_get(path, 'geo_blocked_countries', 100.0)) != ['US']:
            raise RuntimeError('Geo-list round-trip failed')
        module.csv_runtime_list_update(path, 'remove_ip', '203.0.113.7', '', 100.0)
        if json.loads(module.csv_kv_get(path, 'exemptions', 100.0))['ips'] != []:
            raise RuntimeError('Exemption removal failed')
        module.csv_log_append(str(Path(directory) / 'access.csv'), ['path'], ['/preflight'], False)
        module.csv_log_close(str(Path(directory) / 'access.csv'))
        keywords = str(Path(directory) / 'keywords.csv')
        module.csv_keywords_update(keywords, 'preflight', ['sample'], set())
        if module.csv_read_set(keywords, 'keyword', True) != {'sample'}:
            raise RuntimeError('Keyword batch round-trip failed')
    report['smoke_test_passed'] = True
    return report


if __name__ == '__main__':
    try:
        result = check()
    except Exception as exc:
        result = {'smoke_test_passed': False, 'error_type': type(exc).__name__}
    print(json.dumps(result, indent=2))
    raise SystemExit(0 if result['smoke_test_passed'] else 1)
