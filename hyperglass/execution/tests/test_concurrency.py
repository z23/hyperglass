"""Per-device in-flight cap and timeout teardown."""

# Standard Library
from types import SimpleNamespace
from unittest.mock import Mock
from threading import Event, Lock

# Third Party
import anyio
import pytest
import paramiko
from pydantic import SecretStr
from netmiko.base_connection import BaseConnection

# Project
from hyperglass.execution import main as execution_main
from hyperglass.execution.drivers import ssh_netmiko
from hyperglass.execution.concurrency import DeviceConcurrencySlot, DeviceConcurrencyLimiter
from hyperglass.exceptions.public import DeviceBusy, DeviceTimeout
from hyperglass.models.config.messages import Messages
from hyperglass.settings import Settings


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

    client = Redis.from_url(str(Settings.redis_dsn), socket_connect_timeout=0.5)
    try:
        client.ping()
    except Exception:  # noqa: BLE001
        return None
    return client


@pytest.mark.skipif(_live_redis() is None, reason="configured Redis is unavailable")
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


class SingleSlotLimiter(FakeLimiter):
    """Track one occupied slot across the event loop and worker."""

    _ttl_ms = 5_000

    def __init__(self):
        super().__init__()
        self.occupied = False
        self.lock = Lock()

    def acquire(self, device_id, limit):
        """Admit at most one worker."""
        with self.lock:
            if self.occupied:
                return None
            self.occupied = True
            return super().acquire(device_id, limit)

    def release(self, device_id, token):
        """Make the slot available again."""
        with self.lock:
            self.occupied = False
            super().release(device_id, token)

    def renew(self, device_id, token):
        """Keep the fake slot from expiring."""
        return True


@pytest.fixture
def blocked_worker(monkeypatch):
    """Exercise execute and the real Netmiko worker without a network device."""
    started, unblock, finished = Event(), Event(), Event()
    params = SimpleNamespace(request_timeout=1.05, messages=Messages())
    state = SimpleNamespace(params=params, redis=None)
    monkeypatch.setattr(execution_main, "use_state", lambda key=None: state)
    monkeypatch.setattr(ssh_netmiko, "use_state", lambda key: params)
    monkeypatch.setattr("hyperglass.state.use_state", lambda key: params)
    limiter = SingleSlotLimiter()
    monkeypatch.setattr(DeviceConcurrencyLimiter, "from_state", classmethod(lambda cls, s: limiter))
    device = SimpleNamespace(
        id="r1",
        name="Router 1",
        driver="netmiko",
        proxy=None,
        max_concurrent_queries=1,
        platform="cisco_ios",
        _target="192.0.2.1",
        port=22,
        driver_config={},
        get_device_type=lambda: "cisco_ios",
        credential=SimpleNamespace(_method="password", username="test", password=SecretStr("test")),
    )
    query = SimpleNamespace(device=device, summary=lambda: "q")

    class Driver(ssh_netmiko.NetmikoConnection):
        """Bypass query construction while retaining the actual worker lifecycle."""

        def __init__(self, device, query):
            self.device, self.query_data, self.query = device, query, ("show route",)

        async def response(self, output):
            """Return the collected output."""
            return "\n".join(output)

        def _collect(self, host=None, port=None):
            """Signal completion only after disconnect has returned."""
            try:
                return super()._collect(host, port)
            finally:
                finished.set()

    monkeypatch.setattr(execution_main, "map_driver", lambda name: Driver)
    transport = Mock()
    transport.send_command.return_value = "output"

    def connect(**kwargs):
        started.set()
        if not unblock.wait(5):
            raise RuntimeError("test did not unblock constructor")
        return transport

    transport.disconnect.side_effect = finished.set
    factory = Mock(side_effect=connect)
    monkeypatch.setattr(ssh_netmiko, "ConnectHandler", factory)
    yield SimpleNamespace(
        limiter=limiter,
        query=query,
        started=started,
        unblock=unblock,
        finished=finished,
        transport=transport,
        factory=factory,
    )
    unblock.set()
    if started.is_set():
        assert finished.wait(2), "worker did not finish during fixture cleanup"


async def wait_for_event(event):
    """Bound waits without consuming the worker-thread pool."""
    with anyio.fail_after(2):
        while not event.is_set():
            await anyio.sleep(0.005)


@pytest.mark.asyncio
async def test_timeout_retains_slot_until_constructor_worker_finishes(blocked_worker):
    worker = blocked_worker
    with pytest.raises(DeviceTimeout):
        await execution_main.execute(worker.query)
    assert worker.started.is_set()
    assert worker.limiter.occupied is True
    with pytest.raises(DeviceBusy):
        await execution_main.execute(worker.query)
    assert worker.factory.call_count == 1
    worker.unblock.set()
    await wait_for_event(worker.finished)
    with anyio.fail_after(2):
        while worker.limiter.occupied:
            await anyio.sleep(0.005)
    worker.transport.send_command.assert_not_called()
    assert await execution_main.execute(worker.query) == "output"


@pytest.mark.asyncio
async def test_caller_cancellation_retains_slot_until_worker_finishes(blocked_worker):
    import asyncio

    worker = blocked_worker
    task = asyncio.create_task(execution_main.execute(worker.query))
    await wait_for_event(worker.started)
    task.cancel()
    with pytest.raises(asyncio.CancelledError):
        await task
    assert worker.limiter.occupied is True
    with pytest.raises(DeviceBusy):
        await execution_main.execute(worker.query)
    worker.unblock.set()
    await wait_for_event(worker.finished)
    worker.transport.send_command.assert_not_called()


@pytest.mark.asyncio
async def test_timeout_retains_slot_through_disconnect(blocked_worker):
    worker = blocked_worker
    worker.factory.side_effect = None
    worker.factory.return_value = worker.transport

    def disconnect():
        worker.started.set()
        if not worker.unblock.wait(5):
            raise RuntimeError("test did not unblock disconnect")
        worker.finished.set()

    worker.transport.disconnect.side_effect = disconnect
    with pytest.raises(DeviceTimeout):
        await execution_main.execute(worker.query)
    assert worker.started.is_set()
    assert worker.limiter.occupied is True
    worker.unblock.set()
    await wait_for_event(worker.finished)


def test_cancelled_slot_prevents_late_worker_from_opening_a_connection():
    limiter = SingleSlotLimiter()
    token = limiter.acquire("r1", 1)
    slot = DeviceConcurrencySlot(limiter, "r1", token)
    connect = Mock()
    slot.release()
    slot.run(connect)
    connect.assert_not_called()
    assert limiter.released == [("r1", token)]


@pytest.mark.asyncio
async def test_queued_cancellation_releases_slot_without_starting_worker(blocked_worker):
    import asyncio

    worker = blocked_worker
    pool = anyio.to_thread.current_default_thread_limiter()
    previous_capacity = pool.total_tokens
    occupied, unblock_pool = Event(), Event()

    def occupy_pool():
        occupied.set()
        unblock_pool.wait(10)

    pool.total_tokens = 1
    holder = asyncio.create_task(anyio.to_thread.run_sync(occupy_pool))
    try:
        await wait_for_event(occupied)
        task = asyncio.create_task(execution_main.execute(worker.query))
        with anyio.fail_after(2):
            while not worker.limiter.occupied:
                await anyio.sleep(0.005)
        task.cancel()
        with pytest.raises(asyncio.CancelledError):
            await task
        assert worker.limiter.occupied is False
        unblock_pool.set()
        await holder
        await anyio.sleep(0.01)
        worker.factory.assert_not_called()
    finally:
        unblock_pool.set()
        await holder
        pool.total_tokens = previous_capacity


@pytest.mark.asyncio
async def test_live_worker_renews_slot_past_redis_ttl(blocked_worker, monkeypatch):
    redis = _live_redis()
    if redis is None:
        pytest.skip("configured Redis is unavailable")
    worker = blocked_worker
    key = "hyperglass-worker-renew-test.r1"
    redis.delete(key)
    limiter = DeviceConcurrencyLimiter(redis, key=lambda _: key, ttl_seconds=1)
    monkeypatch.setattr(DeviceConcurrencyLimiter, "from_state", classmethod(lambda cls, s: limiter))
    try:
        with pytest.raises(DeviceTimeout):
            await execution_main.execute(worker.query)
        await anyio.sleep(1.3)
        assert limiter.acquire("r1", 1) is None
        assert redis.zcard(key) == 1
        worker.unblock.set()
        with anyio.fail_after(2):
            while redis.zcard(key):
                await anyio.sleep(0.005)
        token = limiter.acquire("r1", 1)
        assert token is not None
        limiter.release("r1", token)
        assert limiter.renew("r1", token) is False
        assert redis.zcard(key) == 0
    finally:
        worker.unblock.set()
        await wait_for_event(worker.finished)
        redis.delete(key)


@pytest.mark.asyncio
async def test_failed_shell_open_closes_authenticated_client_before_release(
    blocked_worker, monkeypatch
):
    clients = []

    def make_client(connection):
        client = Mock(spec=paramiko.SSHClient)
        client.invoke_shell.side_effect = paramiko.ChannelException(1, "shell refused")
        clients.append(client)
        return client

    # Run pinned Netmiko's real initialization/establishment; replace only SSH I/O.
    monkeypatch.setattr(BaseConnection, "_build_ssh_client", make_client)
    monkeypatch.setattr(ssh_netmiko, "ConnectHandler", BaseConnection)
    for _ in range(2):
        with pytest.raises(paramiko.ChannelException):
            await execution_main.execute(blocked_worker.query)
        assert blocked_worker.limiter.occupied is False
        for client in clients:
            client.close.assert_called_once_with()
