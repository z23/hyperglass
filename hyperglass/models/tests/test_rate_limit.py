"""Regression tests for query-endpoint rate limiting.

These pin the guarantees of the rate-limit config:

1. Rate limiting is enabled by default (the query endpoint is unauthenticated
   and each request opens a live device connection).
2. Only `/api/query` is limited; the UI, static assets, and read-only info
   endpoints are never throttled.
3. Disabling rate limiting yields no config/middleware.
"""

# Standard Library
import re

# Third Party
import pytest
from litestar import Litestar, get, post
from litestar.testing import TestClient

# Project
from hyperglass.models.config.rate_limit import RATE_LIMIT_EXCLUDE, RateLimit


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
