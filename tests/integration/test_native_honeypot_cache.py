"""Opt-in real Redis test: independent native workers share form timing."""
import os
import subprocess
import sys
import uuid

import pytest

from tests.core.test_honeypot_cache import make_client

pytestmark = pytest.mark.skipif(not os.environ.get('AIWAF_TEST_REDIS_URL'),
    reason='Set AIWAF_TEST_REDIS_URL to a dedicated test Redis instance')


@pytest.mark.parametrize('framework', ['flask', 'fastapi'])
def test_redis_timing_across_processes(framework, tmp_path):
    url = os.environ.get('AIWAF_TEST_REDIS_URL')
    namespace = 'aiwaf:test:honeypot:' + uuid.uuid4().hex
    config = {'honeypot_backend': 'redis', 'honeypot_redis_url': url,
              'honeypot_cache_namespace': namespace, 'min_form_time': 120}
    first = make_client(framework, tmp_path / 'first', None, **config)
    assert first.get('/form').status_code == 200
    # Secrets stay in the inherited environment, not the command line.
    env = {**os.environ, 'AIWAF_TEST_CACHE_NAMESPACE': namespace,
           'AIWAF_TEST_CACHE_DIR': str(tmp_path / 'second'), 'AIWAF_TEST_FRAMEWORK': framework}
    code = '''
import os
from tests.core.test_honeypot_cache import make_client
c = make_client(os.environ['AIWAF_TEST_FRAMEWORK'], os.environ['AIWAF_TEST_CACHE_DIR'], None,
    honeypot_backend='redis', honeypot_redis_url=os.environ['AIWAF_TEST_REDIS_URL'],
    honeypot_cache_namespace=os.environ['AIWAF_TEST_CACHE_NAMESPACE'], min_form_time=120)
assert c.post('/form').status_code == 403
'''
    subprocess.run([sys.executable, '-c', code], env=env, check=True, timeout=60)
