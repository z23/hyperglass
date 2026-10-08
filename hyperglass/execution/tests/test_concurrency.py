"""Per-device in-flight cap and timeout teardown."""

# Standard Library
from types import SimpleNamespace
from unittest.mock import Mock

# Third Party
import anyio
import pytest

# Project
from hyperglass.execution import main as execution_main
from hyperglass.execution.concurrency import DeviceConcurrencyLimiter
from hyperglass.exceptions.public import DeviceBusy, DeviceTimeout
from hyperglass.models.config.messages import Messages


def _limiter(redis):
    return DeviceConcurrencyLimiter(redis, key=lambda k: f"hyperglass.{k}", ttl_seconds=180)


def test_acquire_returns_token_when_allowed():
    redis = Mock()
    redis.eval.return_value = [1, 3]
    token = _limiter(redis).acquire("r1", 10)
    assert isinstance(token, str) and len(token) == 16
    script, nkeys, key, now_ms, sent_token, ttl_ms, limit = redis.eval.call_args.args
    assert nkeys == 1
    assert key == "hyperglass.device.inflight.r1"
    assert sent_token == token
    assert ttl_ms == 180_000
    assert limit == 10
    assert isinstance(now_ms, int)


def test_acquire_returns_none_when_full():
    redis = Mock()
    redis.eval.return_value = [0, 10]
    assert _limiter(redis).acquire("r1", 10) is None


def test_release_removes_token_and_swallows_errors():
    redis = Mock()
    limiter = _limiter(redis)
    limiter.release("r1", "abc")
    redis.zrem.assert_called_once_with("hyperglass.device.inflight.r1", "abc")
    redis.zrem.side_effect = ConnectionError("gone")
    limiter.release("r1", "abc")  # must not raise


def test_from_state_uses_shared_redis_and_request_budget():
    instance = Mock()
    state = SimpleNamespace(
        params=SimpleNamespace(request_timeout=90),
        redis=SimpleNamespace(instance=instance, key=lambda k: f"ns.{k}"),
    )
    limiter = DeviceConcurrencyLimiter.from_state(state)
    assert limiter._redis is instance
    assert limiter._ttl_ms == 180_000
    assert limiter._device_key("r1") == "ns.device.inflight.r1"


def _live_redis():
    # Third Party
    from redis import Redis

    client = Redis.from_url("redis://localhost:6379/15", socket_connect_timeout=0.5)
    try:
        client.ping()
    except Exception:  # noqa: BLE001
        return None
    return client


@pytest.mark.skipif(_live_redis() is None, reason="no local Redis on localhost:6379")
def test_live_redis_cap_is_atomic_and_self_healing():
    redis = _live_redis()
    key = "hyperglass-test.device.inflight.r1"
    redis.delete(key)
    limiter = DeviceConcurrencyLimiter(redis, key=lambda k: f"hyperglass-test.{k}", ttl_seconds=1)
    tokens = [limiter.acquire("r1", 3) for _ in range(5)]
    assert sum(t is not None for t in tokens) == 3
    limiter.release("r1", next(t for t in tokens if t))
    assert limiter.acquire("r1", 3) is not None
    assert limiter.acquire("r1", 3) is None
    # Leaked slots expire with the TTL.
    import time

    time.sleep(1.2)
    assert limiter.acquire("r1", 3) is not None
    redis.delete(key)


# --- execute() wiring -------------------------------------------------------


class FakeLimiter:
    """Records acquire/release calls and can be told to refuse."""

    def __init__(self, allow=True):
        self.allow = allow
        self.acquired = []
        self.released = []

    def acquire(self, device_id, limit):
        """Return a token, or None when told to refuse."""
        self.acquired.append((device_id, limit))
        return "tok" if self.allow else None

    def release(self, device_id, token):
        """Record the release."""
        self.released.append((device_id, token))


class FakeDriver:
    """Stands in for a Connection; `delay` is a class attribute set by tests."""

    instances = []
    delay = 0

    def __init__(self, device, query):
        self.device = device
        self.query_data = query
        self.collect_calls = 0
        self.aborted = False
        FakeDriver.instances.append(self)

    async def collect(self, *_):
        """Pretend to talk to the device, optionally slowly."""
        self.collect_calls += 1
        if self.delay:
            await anyio.sleep(self.delay)
        return ("output",)

    def abort(self):
        """Record that the request timeout tore the session down."""
        self.aborted = True

    async def response(self, output):
        """Join raw output like the real driver."""
        return "\n".join(output)


@pytest.fixture
def wiring(monkeypatch):
    FakeDriver.instances.clear()
    params = SimpleNamespace(request_timeout=2, messages=Messages())
    state = SimpleNamespace(params=params, redis=None)
    monkeypatch.setattr(execution_main, "use_state", lambda key=None: state)
    monkeypatch.setattr("hyperglass.state.use_state", lambda key=None: params)
    monkeypatch.setattr(execution_main, "map_driver", lambda name: FakeDriver)
    limiter = FakeLimiter()
    monkeypatch.setattr(DeviceConcurrencyLimiter, "from_state", classmethod(lambda cls, s: limiter))
    device = SimpleNamespace(
        id="r1", name="Router 1", driver="netmiko", proxy=None, max_concurrent_queries=4
    )
    query = SimpleNamespace(device=device, summary=lambda: "q")
    return limiter, query


@pytest.mark.asyncio
async def test_execute_acquires_and_releases_slot(wiring):
    limiter, query = wiring
    assert await execution_main.execute(query) == "output"
    assert limiter.acquired == [("r1", 4)]
    assert limiter.released == [("r1", "tok")]


@pytest.mark.asyncio
async def test_execute_rejects_with_503_when_device_is_full(wiring):
    limiter, query = wiring
    limiter.allow = False
    with pytest.raises(DeviceBusy) as excinfo:
        await execution_main.execute(query)
    assert excinfo.value.status_code == 503
    assert "Router 1 is busy" in excinfo.value.message
    assert FakeDriver.instances[0].collect_calls == 0
    assert limiter.released == []


@pytest.mark.asyncio
async def test_execute_aborts_driver_and_releases_on_timeout(wiring):
    limiter, query = wiring
    FakeDriver.delay = 5  # longer than request_timeout - 1
    try:
        with pytest.raises(DeviceTimeout):
            await execution_main.execute(query)
    finally:
        FakeDriver.delay = 0
    driver = FakeDriver.instances[0]
    assert driver.aborted is True
    assert limiter.released == [("r1", "tok")]
