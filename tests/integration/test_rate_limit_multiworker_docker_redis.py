import multiprocessing as mp
import subprocess
import uuid

import pytest
from flask import Flask
from fastapi import FastAPI
from fastapi.testclient import TestClient

from aiwaf.flask.rate_limit_middleware import RateLimitMiddleware as FlaskRateLimit
from aiwaf.fast import AIWAF as FastAIWAF

from .docker_redis import start_docker_redis, stop_docker_container


def _flask_worker(redis_url: str, path: str, conn):
    try:
        app = Flask(__name__)
        app.config.update(
            {
                "TESTING": True,
                "AIWAF_EXEMPT_PATHS": set(),
                # Avoid reading global CSV allowlist that may exempt localhost.
                "AIWAF_USE_CSV": False,
                "AIWAF_RATE_WINDOW": 60,
                "AIWAF_RATE_MAX": 1,
                "AIWAF_RATE_FLOOD": 100,
                "AIWAF_RATE_CACHE_BACKEND": "redis",
                "AIWAF_REDIS_URL": redis_url,
            }
        )
        FlaskRateLimit(app)

        @app.route(path)
        def rl():
            return "ok"

        headers = {"User-Agent": "Test Browser 1.0"}
        with app.test_client() as client:
            resp = client.get(path, headers=headers)
            conn.send(resp.status_code)
    except Exception as exc:  # pragma: no cover
        conn.send({"error": str(exc)})
    finally:
        conn.close()


def _fast_worker(redis_url: str, path: str, conn):
    try:
        app = FastAPI()

        @app.get(path)
        async def rl():
            return {"ok": True}

        FastAIWAF(
            app,
            header_validation={"enabled": False},
            honeypot={"enabled": False},
            rate_limiting={
                "enabled": True,
                "window_seconds": 60,
                "max_requests": 1,
                "flood_threshold": 100,
                "cache_backend": "redis",
                "redis_url": redis_url,
            },
        )
        client = TestClient(app)
        resp = client.get(path)
        conn.send(resp.status_code)
    except Exception as exc:  # pragma: no cover
        conn.send({"error": str(exc)})
    finally:
        conn.close()


@pytest.mark.slow
def test_rate_limiting_shared_across_workers_docker_redis():
    """
    Spins up Redis in Docker and verifies both Flask and FastAPI rate limiting
    share counters across processes (i.e., "multiple workers").
    """
    try:
        subprocess.run(["docker", "version"], check=True, capture_output=True, text=True, timeout=10)
    except Exception:
        pytest.skip("Docker not available")

    redis = start_docker_redis()
    try:
        ctx = mp.get_context("spawn")
        unique = uuid.uuid4().hex

        # Flask: first request 200, second request from another worker 429.
        flask_path = f"/rl-flask-{unique}"
        p1r, p1w = ctx.Pipe(duplex=False)
        p1 = ctx.Process(target=_flask_worker, args=(redis.url, flask_path, p1w))
        p1.start()
        s1 = p1r.recv()
        p1.join(20)
        assert p1.exitcode == 0
        assert s1 == 200

        p2r, p2w = ctx.Pipe(duplex=False)
        p2 = ctx.Process(target=_flask_worker, args=(redis.url, flask_path, p2w))
        p2.start()
        s2 = p2r.recv()
        p2.join(20)
        assert p2.exitcode == 0
        assert s2 == 429

        # FastAPI: same behavior.
        fast_path = f"/rl-fast-{unique}"
        f1r, f1w = ctx.Pipe(duplex=False)
        f1 = ctx.Process(target=_fast_worker, args=(redis.url, fast_path, f1w))
        f1.start()
        fs1 = f1r.recv()
        f1.join(20)
        assert f1.exitcode == 0
        assert fs1 == 200

        f2r, f2w = ctx.Pipe(duplex=False)
        f2 = ctx.Process(target=_fast_worker, args=(redis.url, fast_path, f2w))
        f2.start()
        fs2 = f2r.recv()
        f2.join(20)
        assert f2.exitcode == 0
        assert fs2 == 429
    finally:
        stop_docker_container(redis.container_id)
