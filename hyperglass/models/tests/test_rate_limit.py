"""Regression tests for query-endpoint rate limiting.

These pin the guarantees of the rate-limit config:

1. Rate limiting is enabled by default (the query endpoint is unauthenticated
   and each request opens a live device connection).
2. Only `/api/query` is limited; the UI, static assets, and read-only info
   endpoints are never throttled.
3. Disabling rate limiting yields no config/middleware.
4. The counter is backed by a shared store, so the configured limit holds
   across worker processes rather than being multiplied by the worker count.
"""

# Standard Library
import re

# Third Party
import pytest
from litestar import Litestar, get, post
from litestar.stores.redis import RedisStore
from litestar.stores.memory import MemoryStore
from litestar.testing import TestClient

# Project
from hyperglass.models.config.rate_limit import (
    RATE_LIMIT_EXCLUDE,
    RATE_LIMIT_STORE_NAME,
    RateLimit,
)


@post("/api/query")
async def _query() -> dict:
    return {"ok": True}


@get("/api/info")
async def _info() -> dict:
    return {"ok": True}


def test_rate_limit_enabled_by_default():
    """The query endpoint must be rate limited out of the box."""
    rl = RateLimit()
    assert rl.enable is True
    assert rl.to_litestar_config() is not None


def test_rate_limit_disabled_yields_no_config():
    """A disabled rate limit must produce no config (hence no middleware)."""
    assert RateLimit(enable=False).to_litestar_config() is None


def test_query_endpoint_is_limited():
    """Requests to /api/query beyond the limit return HTTP 429."""
    config = RateLimit(period="minute", limit=2).to_litestar_config()
    app = Litestar([_query, _info], middleware=[config.middleware])

    with TestClient(app=app) as client:
        codes = [client.post("/api/query").status_code for _ in range(4)]

    assert codes[:2] == [201, 201]
    assert codes[2] == 429
    assert 429 in codes


def test_non_query_endpoints_are_not_limited():
    """Read-only endpoints must never be throttled, even past the limit."""
    config = RateLimit(period="minute", limit=2).to_litestar_config()
    app = Litestar([_query, _info], middleware=[config.middleware])

    with TestClient(app=app) as client:
        codes = [client.get("/api/info").status_code for _ in range(6)]

    assert all(code == 200 for code in codes)


@pytest.mark.parametrize(
    ("path", "excluded"),
    [
        ("/api/query", False),
        ("/api/info", True),
        ("/api/devices", True),
        ("/", True),
        ("/ui/index.html", True),
    ],
)
def test_exclude_pattern_targets_only_query(path, excluded):
    """The exclude pattern must match every path except /api/query."""
    pattern = re.compile("|".join(RATE_LIMIT_EXCLUDE))
    assert bool(pattern.match(path)) is excluded


def test_config_targets_the_named_store():
    """The config must point at the store name the app registers Redis under."""
    assert RateLimit().to_litestar_config().store == RATE_LIMIT_STORE_NAME


def test_redis_store_is_redis_backed():
    """The rate-limit store must be Redis-backed, not per-process memory.

    Building the store does not open a connection, so no live Redis is needed.
    """
    store = RateLimit.redis_store("redis://localhost:6379/1")
    assert isinstance(store, RedisStore)


def _limited_app(store):
    """A minimal app whose /api/query is limited to 2/min via `store`."""
    config = RateLimit(period="minute", limit=2).to_litestar_config()
    return Litestar([_query], middleware=[config.middleware], stores={config.store: store})


def test_shared_store_enforces_limit_across_workers():
    """Two app instances sharing one store == workers sharing one Redis.

    The limit (2) must hold across both, not per-instance.
    """
    shared = MemoryStore()
    worker_a = _limited_app(shared)
    worker_b = _limited_app(shared)

    with TestClient(app=worker_a) as client_a, TestClient(app=worker_b) as client_b:
        assert client_a.post("/api/query").status_code == 201
        assert client_b.post("/api/query").status_code == 201
        # Budget of 2 is now spent; the next request is rejected regardless of
        # which worker handles it.
        assert client_a.post("/api/query").status_code == 429
        assert client_b.post("/api/query").status_code == 429


def test_unshared_stores_multiply_the_limit():
    """Without a shared store, each worker counts independently (the #7 bug).

    This is the failure mode the shared store fixes: with per-instance stores
    the effective limit is `workers * limit`.
    """
    worker_a = _limited_app(MemoryStore())
    worker_b = _limited_app(MemoryStore())

    with TestClient(app=worker_a) as client_a, TestClient(app=worker_b) as client_b:
        # Each worker independently allows 2, so 4 requests succeed overall.
        codes = [
            client_a.post("/api/query").status_code,
            client_b.post("/api/query").status_code,
            client_a.post("/api/query").status_code,
            client_b.post("/api/query").status_code,
        ]

    assert codes == [201, 201, 201, 201]
