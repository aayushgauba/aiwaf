"""CSV replacement, keyword removal, and logger lifecycle through Flask adapters."""
import csv

import pytest
from flask import Flask
from aiwaf.flask import storage
from aiwaf.core.native_runtime import native_override


@pytest.mark.parametrize('native_enabled', [False, True])
def test_csv_policy_replacement_and_keyword_removal(tmp_path, native_enabled):
    app = Flask(__name__)
    app.config.update(AIWAF_USE_CSV=True, AIWAF_DATA_DIR=str(tmp_path), AIWAF_USE_RUST=native_enabled)
    with app.app_context(), native_override(native_enabled):
        store = storage.get_keyword_store()
        store.add_keyword('keep')
        store.add_keyword('remove')
        store.remove_keyword('remove')
        store.remove_keyword('absent')
        assert set(store.get_top_keywords(10)) == {'keep'}
        storage._rewrite_csv_geo_blocked_countries({'us', 'GB'})
        assert storage._read_csv_geo_blocked_countries() == {'US', 'GB'}
        storage._rewrite_csv_path_exemptions({'/health': 'probe', '/ready': 'readiness'})
        assert storage._read_csv_path_exemptions() == {'/health': 'probe', '/ready': 'readiness'}
        storage._rewrite_csv_geo_blocked_countries(set())
        storage._rewrite_csv_path_exemptions({})
        assert not storage._read_csv_geo_blocked_countries()
        assert not storage._read_csv_path_exemptions()


def test_python_keyword_probe_context_is_enforced(tmp_path):
    from aiwaf.flask.ip_and_keyword_block_middleware import IPAndKeywordBlockMiddleware
    app = Flask(__name__)
    app.config.update(AIWAF_USE_CSV=True, AIWAF_DATA_DIR=str(tmp_path),
                      AIWAF_USE_RUST=False, AIWAF_EXEMPT_PATHS=[])
    IPAndKeywordBlockMiddleware(app)
    response = app.test_client().get('/wp-content/customshell.php',
        environ_base={'REMOTE_ADDR': '203.0.113.55'})
    assert response.status_code == 403
    with app.app_context():
        assert storage.is_ip_blacklisted('203.0.113.55')


def test_csv_logger_close_and_reopen_preserves_rows(tmp_path):
    from aiwaf.flask.logging_middleware import AIWAFLoggingMiddleware
    app = Flask(__name__)
    app.config.update(AIWAF_LOG_DIR=str(tmp_path), AIWAF_LOG_FORMAT='csv')
    logger = AIWAFLoggingMiddleware(app)
    app.add_url_rule('/docs', view_func=lambda: 'ok')
    try:
        assert app.test_client().get('/docs').status_code == 200
        logger.close()
        assert app.test_client().get('/docs').status_code == 200
        logger.close()
        with logger.access_log_file.open(newline='', encoding='utf-8') as file:
            rows = list(csv.DictReader(file))
        assert len(rows) == 2
        assert [row['path'] for row in rows] == ['/docs', '/docs']
    finally:
        logger.close()
