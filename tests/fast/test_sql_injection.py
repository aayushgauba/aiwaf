import unittest
from unittest.mock import MagicMock, patch
from fastapi import FastAPI, Request
from fastapi.responses import JSONResponse
from fastapi.testclient import TestClient
from aiwaf.fast.middleware.ip_and_keyword_block_middleware import IPAndKeywordBlockMiddleware
from tests.sql_policy.cases import FrameworkCases, wire_body, echo_body


class FastAPIPolicyTests(FrameworkCases, unittest.TestCase):
    def send(self, payload, mode='block', max_bytes=65536, exempt=False, query='', content_type='application/json'):
        app = FastAPI()
        @app.post('/login')
        async def login(request: Request):
            return JSONResponse(echo_body(await request.body(), request.headers['content-type']), status_code=401)
        app.add_middleware(IPAndKeywordBlockMiddleware, sql_injection_mode=mode, payload_max_bytes=max_bytes)
        module = 'aiwaf.fast.middleware.ip_and_keyword_block_middleware.'
        store = MagicMock(); store.get_top_keywords.return_value = []
        with patch(module + 'is_exempt', return_value=exempt), patch(module + 'should_apply_middleware', return_value=True), \
             patch(module + 'BlocklistManager.is_blocked', return_value=False), patch(module + 'get_keyword_store', return_value=store):
            with TestClient(app) as client:
                result = client.post('/login?' + query, content=wire_body(payload), headers={'content-type': content_type})
        return result.status_code, result.json()
