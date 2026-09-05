"""Regression tests for query-endpoint rate limiting.

These pin the guarantees of the rate-limit config:

1. Rate limiting is enabled by default at 10/minute (the query endpoint is
   unauthenticated and each request opens a live device connection).
2. Only `/api/query` is limited; the UI, static assets, and read-only info
   endpoints are never throttled.
3. Disabling rate limiting yields no config/middleware.
4. The counter is backed by a shared store, so the configured limit holds
   across worker processes rather than being multiplied by the worker count.
5. Values are configurable via environment variables, with the config-file
   value taking precedence over the environment.
"""

# Standard Library
import re
import time
import uuid
import shutil
import asyncio
import subprocess
from pathlib import Path
from configparser import ConfigParser

# Third Party
import pytest
import yaml
from uvicorn import Config
from httpx import AsyncClient, ASGITransport
from redis import Redis
from redis.exceptions import ConnectionError as RedisConnectionError
from litestar import Litestar, get, post
from litestar.stores.redis import RedisStore
from litestar.stores.memory import MemoryStore
from litestar.testing import TestClient
from uvicorn.middleware.proxy_headers import ProxyHeadersMiddleware

# Project
from hyperglass.models.config.rate_limit import (
    RATE_LIMIT_EXCLUDE,
    RATE_LIMIT_STORE_NAME,
    RateLimit,
)

RATE_LIMIT_ENV_VARS = (
    "HYPERGLASS_RATE_LIMIT",
    "HYPERGLASS_RATE_LIMIT_PERIOD",
    "HYPERGLASS_RATE_LIMIT_ENABLE",
)


@pytest.fixture(scope="module")
def redis_url(tmp_path_factory):
    """Run an isolated Redis on a Unix socket; never use or flush ambient Redis."""
    executable = shutil.which("redis-server")
    if executable is None:
        pytest.skip("redis-server executable is required for rate-limit integration tests")
    directory = tmp_path_factory.mktemp("rate-limit")
    socket = directory / "redis.sock"
    process = subprocess.Popen(  # noqa: S603
        [  # noqa: S603
            executable,
            "--port",
            "0",
            "--unixsocket",
            str(socket),
            "--unixsocketperm",
            "700",
            "--save",
            "",
            "--appendonly",
            "no",
            "--dir",
            str(directory),
        ],
        stdout=subprocess.DEVNULL,
        stderr=subprocess.STDOUT,
    )
    url = f"unix://{socket}?db=0"
    client = Redis.from_url(url)
    try:
        deadline = time.monotonic() + 5
        while True:
            try:
                if client.ping():
                    break
            except RedisConnectionError:
                if process.poll() is not None or time.monotonic() >= deadline:
                    pytest.fail("Isolated redis-server did not start")
                time.sleep(0.02)
        yield url
    finally:
        client.close()
        process.terminate()
        process.wait(timeout=5)


@pytest.fixture
def store_factory(redis_url):
    """Separate worker clients share only the Redis namespace for this test."""
    namespace = f"test-rate-limit-{uuid.uuid4().hex}"

    def create(*, separate=False):
        store = RateLimit.redis_store(redis_url)
        store.namespace = uuid.uuid4().hex if separate else namespace
        return store

    return create


@pytest.fixture(autouse=True)
def _clean_rate_limit_env(monkeypatch):
    """Ensure the ambient environment can't skew default-behavior assertions."""
    for var in RATE_LIMIT_ENV_VARS:
        monkeypatch.delenv(var, raising=False)


@post("/api/query")
async def _query() -> dict:
    return {"ok": True}


@get("/api/info")
async def _info() -> dict:
    return {"ok": True}


def test_defaults():
    """Rate limiting must be on at 10/minute out of the box."""
    rl = RateLimit()
    assert rl.enable is True
    assert rl.period == "minute"
    assert rl.limit == 10
    assert rl.to_litestar_config() is not None


def test_rate_limit_disabled_yields_no_config():
    """A disabled rate limit must produce no config (hence no middleware)."""
    assert RateLimit(enable=False).to_litestar_config() is None


def test_env_var_overrides_default(monkeypatch):
    """HYPERGLASS_RATE_LIMIT* environment variables configure the limit."""
    monkeypatch.setenv("HYPERGLASS_RATE_LIMIT", "3")
    monkeypatch.setenv("HYPERGLASS_RATE_LIMIT_PERIOD", "hour")
    monkeypatch.setenv("HYPERGLASS_RATE_LIMIT_ENABLE", "false")
    rl = RateLimit()
    assert rl.limit == 3
    assert rl.period == "hour"
    assert rl.enable is False


def test_config_value_takes_precedence_over_env(monkeypatch):
    """An explicit config-file value must win over the environment variable."""
    monkeypatch.setenv("HYPERGLASS_RATE_LIMIT", "3")
    assert RateLimit(limit=5).limit == 5


def test_query_endpoint_is_limited(store_factory):
    """Requests to /api/query beyond the limit return HTTP 429."""
    config = RateLimit(limit=2).to_litestar_config()
    app = Litestar(
        [_query, _info], middleware=[config.middleware], stores={config.store: store_factory()}
    )

    with TestClient(app=app) as client:
        codes = [client.post("/api/query").status_code for _ in range(4)]

    assert codes[:2] == [201, 201]
    assert codes[2] == 429
    assert 429 in codes


def test_non_query_endpoints_are_not_limited(store_factory):
    """Read-only endpoints must never be throttled, even past the limit."""
    config = RateLimit(limit=2).to_litestar_config()
    app = Litestar(
        [_query, _info], middleware=[config.middleware], stores={config.store: store_factory()}
    )

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
    """Build a minimal app whose /api/query is limited to 2/min via `store`."""
    config = RateLimit(limit=2).to_litestar_config()
    return Litestar([_query], middleware=[config.middleware], stores={config.store: store})


def test_shared_store_enforces_limit_across_workers(store_factory):
    """Two app instances with separate connections share one Redis budget.

    The limit (2) must hold across both, not per-instance.
    """
    worker_a = _limited_app(store_factory())
    worker_b = _limited_app(store_factory())

    with TestClient(app=worker_a) as client_a, TestClient(app=worker_b) as client_b:
        assert client_a.post("/api/query").status_code == 201
        assert client_b.post("/api/query").status_code == 201
        # Budget of 2 is now spent; the next request is rejected regardless of
        # which worker handles it.
        assert client_a.post("/api/query").status_code == 429
        assert client_b.post("/api/query").status_code == 429


def test_separate_namespaces_have_independent_budgets(store_factory):
    """Different store namespaces isolate separate applications."""
    worker_a = _limited_app(store_factory(separate=True))
    worker_b = _limited_app(store_factory(separate=True))

    with TestClient(app=worker_a) as client_a, TestClient(app=worker_b) as client_b:
        # Each worker independently allows 2, so 4 requests succeed overall.
        codes = [
            client_a.post("/api/query").status_code,
            client_b.post("/api/query").status_code,
            client_a.post("/api/query").status_code,
            client_b.post("/api/query").status_code,
        ]

    assert codes == [201, 201, 201, 201]


def test_missing_atomic_store_fails_closed():
    """A stock in-memory store must not silently replace shared admission."""
    with TestClient(app=_limited_app(MemoryStore())) as client:
        assert client.post("/api/query").status_code == 500


@pytest.mark.parametrize("header", ["X-Forwarded-For", "X-Real-IP"])
def test_spoofed_forwarding_headers_do_not_change_budget(store_factory, header):
    with TestClient(app=_limited_app(store_factory())) as client:
        codes = [
            client.post("/api/query", headers={header: f"198.51.100.{n}"}).status_code
            for n in range(4)
        ]
    assert codes == [201, 201, 429, 429]


def test_path_aliases_share_budget(store_factory):
    with TestClient(app=_limited_app(store_factory())) as client:
        codes = [
            client.post(path).status_code
            for path in ("/api/query", "/api/query/", "/api//query", "/api/%71uery")
        ]
    assert codes == [201, 201, 429, 429]


@pytest.mark.asyncio
@pytest.mark.parametrize("trusted", [False, True])
@pytest.mark.parametrize("proxy_peer", ["127.0.0.1", "::1", "172.18.0.1"])
async def test_uvicorn_proxy_trust_preserves_client_budgets(
    store_factory, monkeypatch, trusted, proxy_peer
):
    store = store_factory()
    monkeypatch.setenv("FORWARDED_ALLOW_IPS", proxy_peer if trusted else "")
    application = _limited_app(store)
    config = Config(app=application, log_config=None)
    app = ProxyHeadersMiddleware(application, trusted_hosts=config.forwarded_allow_ips)
    try:
        async with AsyncClient(
            transport=ASGITransport(app=app, client=(proxy_peer, 1234)),
            base_url="http://testserver",
        ) as client:
            responses = [
                await client.post(
                    "/api/query",
                    headers={"X-Forwarded-For": f"198.51.100.{n}, 203.0.113.7"},
                )
                for n in range(4)
            ]
            assert [r.status_code for r in responses] == [201, 201, 429, 429]
            different_client = await client.post(
                "/api/query", headers={"X-Forwarded-For": "203.0.113.8"}
            )
            assert different_client.status_code == (201 if trusted else 429)
    finally:
        await store._shutdown()


def test_native_proxy_samples_match_service_trust(monkeypatch):
    """Keep the checked-in proxy upstreams and native service trust paired."""
    samples = Path(__file__).resolve().parents[3] / ".samples"
    service = ConfigParser(interpolation=None)
    service.read(samples / "hyperglass-manual.service")
    variable, peer = service["Service"]["Environment"].strip('"').split("=", 1)
    assert variable == "FORWARDED_ALLOW_IPS"
    assert peer == "::1"
    monkeypatch.setenv(variable, peer)
    assert Config(app=_query, log_config=None).forwarded_allow_ips == peer
    assert "reverse_proxy [::1]:8001" in (samples / "Caddyfile").read_text()
    assert "proxy_pass http://[::1]:8001;" in (samples / "hyperglass.nginx").read_text()
    assert service["Service"]["EnvironmentFile"] == "/etc/hyperglass/hyperglass.env"


def test_compose_passes_proxy_trust_without_overriding_explicit_empty_values():
    compose = Path(__file__).resolve().parents[3] / "compose.yaml"
    environment = yaml.safe_load(compose.read_text())["services"]["hyperglass"]["environment"]
    assert "FORWARDED_ALLOW_IPS=${FORWARDED_ALLOW_IPS-127.0.0.1}" in environment


def test_redis_failure_does_not_admit_a_query(monkeypatch):
    """Simulate failure before admission without connecting to any Redis."""
    store = RateLimit.redis_store("redis://localhost:6379/1")

    async def fail(*args):
        raise RedisConnectionError("unavailable")

    monkeypatch.setattr(store, "admit", fail)
    with TestClient(app=_limited_app(store)) as client:
        assert client.post("/api/query").status_code == 500


def test_rate_limit_headers_can_be_disabled(store_factory):
    config = RateLimit(limit=1).to_litestar_config()
    config.set_rate_limit_headers = False
    app = Litestar([_query], middleware=[config.middleware], stores={config.store: store_factory()})
    with TestClient(app=app) as client:
        responses = [client.post("/api/query") for _ in range(2)]
    assert [r.status_code for r in responses] == [201, 429]
    assert all("RateLimit-Limit" not in r.headers for r in responses)


@pytest.mark.asyncio
async def test_concurrent_workers_cannot_reuse_remaining_allowance(store_factory):
    """Forty simultaneous requests compete for exactly one remaining slot."""
    stores = [store_factory() for _ in range(4)]
    clients = [
        AsyncClient(transport=ASGITransport(app=_limited_app(store)), base_url="http://testserver")
        for store in stores
    ]
    try:
        assert (await clients[0].post("/api/query")).status_code == 201
        responses = await asyncio.gather(*(clients[n % 4].post("/api/query") for n in range(40)))
        assert [r.status_code for r in responses].count(201) == 1
        assert [r.status_code for r in responses].count(429) == 39
        assert all(r.headers["RateLimit-Remaining"] == "0" for r in responses)
        assert all(0 < int(r.headers["RateLimit-Reset"]) <= 60 for r in responses)
    finally:
        for client in clients:
            await client.aclose()
        for store in stores:
            await store._shutdown()


@pytest.mark.asyncio
async def test_rejections_do_not_extend_window_and_expiry_restores_budget(store_factory):
    store = store_factory()
    try:
        assert (await store.admit("client", 1, 1))[:2] == (True, 1)
        allowed, count, ttl = await store.admit("client", 1, 1)
        assert (allowed, count) == (False, 1)
        await asyncio.sleep(0.05)
        assert (await store.admit("client", 1, 1))[2] < ttl
        await asyncio.sleep(1)
        assert (await store.admit("client", 1, 1))[:2] == (True, 1)
        assert (await store.admit("different-client", 1, 1))[:2] == (True, 1)
    finally:
        await store._shutdown()


@pytest.mark.parametrize("key,value", [("period", "hour"), ("enable", False)])
def test_other_config_fields_take_precedence_over_env(monkeypatch, key, value):
    monkeypatch.setenv("HYPERGLASS_RATE_LIMIT_PERIOD", "day")
    monkeypatch.setenv("HYPERGLASS_RATE_LIMIT_ENABLE", "true")
    assert getattr(RateLimit(**{key: value}), key) == value
