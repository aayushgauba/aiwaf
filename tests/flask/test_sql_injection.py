import unittest
from unittest.mock import MagicMock, patch
from flask import Flask, request, jsonify
from aiwaf.flask.ip_and_keyword_block_middleware import IPAndKeywordBlockMiddleware
from tests.sql_policy.cases import FrameworkCases, wire_body, echo_body


class FlaskPolicyTests(FrameworkCases, unittest.TestCase):
    def send(self, payload, mode='block', max_bytes=65536, exempt=False, query='', content_type='application/json'):
        app = Flask(__name__)
        app.config.update(TESTING=True, AIWAF_SQL_INJECTION_MODE=mode, AIWAF_PAYLOAD_MAX_BYTES=max_bytes,
                          AIWAF_ENABLE_KEYWORD_LEARNING=False)
        @app.post('/login')
        def login():
            return jsonify(echo_body(request.get_data(), request.content_type)), 401
        module = 'aiwaf.flask.ip_and_keyword_block_middleware.'
        store = MagicMock(); store.get_top_keywords.return_value = []
        with patch(module + 'is_exempt', return_value=exempt), patch(module + 'should_apply_middleware', return_value=True), \
             patch(module + 'BlocklistManager.is_blocked', return_value=False), patch(module + 'get_keyword_store', return_value=store):
            IPAndKeywordBlockMiddleware(app)
            result = app.test_client().post('/login?' + query, data=wire_body(payload), content_type=content_type)
        return result.status_code, result.get_json()
