"""External lookups must be bounded in time, honour ports, and expire what they cache."""

# Standard Library
import time
import socket
import typing as t
import asyncio

# Third Party
import pytest

# Project
from hyperglass.state import use_state
from hyperglass.state.hooks import _use_state
from hyperglass.exceptions.private import ExternalError
from hyperglass.models.config.params import Params

# Local
from .. import rpki, bgptools
from .._base import BaseExternal
from ..generic import GenericHook


@pytest.fixture
def state() -> t.Generator[t.Any, None, None]:
    _use_state.cache_clear()
    _state = use_state()
    with _state.cache.pipeline() as pipeline:
        pipeline.set("params", Params())
    _use_state.cache_clear()
    yield _state
    _state.clear()
    _use_state.cache_clear()


@pytest.fixture
def listener() -> t.Generator[int, None, None]:
    """Listen on a local TCP port and yield its number."""
    server = socket.socket()
    server.bind(("127.0.0.1", 0))
    server.listen(8)
    yield server.getsockname()[1]
    server.close()


def _closed_port() -> int:
    probe = socket.socket()
    probe.bind(("127.0.0.1", 0))
    port = probe.getsockname()[1]
    probe.close()
    return port


# --- reachability probe ---------------------------------------------------------


@pytest.mark.parametrize(
    ("base_url", "expected"),
    [
        ("https://hooks.example.com", ("hooks.example.com", 443)),
        ("http://hooks.example.com", ("hooks.example.com", 80)),
        ("https://hooks.example.com:8443", ("hooks.example.com", 8443)),
        ("http://127.0.0.1:9000/base/path", ("127.0.0.1", 9000)),
        ("https://[2001:db8::1]:8443", ("2001:db8::1", 8443)),
        ("https://[2001:db8::1]", ("2001:db8::1", 443)),
        ("hooks.example.com", ("hooks.example.com", 443)),
    ],
)
def test_probe_uses_the_host_and_port_of_the_base_url(base_url, expected):
    assert BaseExternal(base_url=base_url)._test_address() == expected


def test_probe_reaches_a_non_default_port(listener):
    assert BaseExternal(base_url=f"http://127.0.0.1:{listener}")._test() is True
    assert asyncio.run(BaseExternal(base_url=f"http://127.0.0.1:{listener}")._atest()) is True


def test_probe_reports_a_refused_connection_as_unreachable(state):
    client = BaseExternal(base_url=f"http://127.0.0.1:{_closed_port()}")
    with pytest.raises(ExternalError):
        client._test()


def test_probe_is_bounded_by_the_session_timeout(state, monkeypatch):
    """An address that never answers must not hold the caller open."""
    seen = {}

    def create_connection(address, timeout=None):
        seen["address"], seen["timeout"] = address, timeout
        raise TimeoutError("timed out")

    monkeypatch.setattr(socket, "create_connection", create_connection)
    client = BaseExternal(base_url="https://hooks.example.com:8443", timeout=3)
    with pytest.raises(ExternalError):
        client._test()
    assert seen == {"address": ("hooks.example.com", 8443), "timeout": 3}


@pytest.mark.parametrize(
    ("host", "expected"),
    [
        ("https://hooks.example.com/hook", "https://hooks.example.com:443"),
        ("https://hooks.example.com:8443/hook", "https://hooks.example.com:8443"),
        ("http://10.0.0.5:9000/in", "http://10.0.0.5:9000"),
    ],
)
def test_generic_webhook_keeps_the_configured_port(host, expected):
    # Project
    from hyperglass.models.config.logging import Http

    hook = GenericHook(Http(provider="generic", host=host))
    assert hook.base_url == expected


# --- bgp.tools ---------------------------------------------------------------------


def test_whois_gives_up_when_the_server_never_answers(state, monkeypatch):
    opened = []

    async def never_answers(*_: t.Any, **__: t.Any):
        opened.append(True)
        await asyncio.sleep(3600)

    monkeypatch.setattr(asyncio, "open_connection", never_answers)
    monkeypatch.setattr(bgptools, "WHOIS_TIMEOUT_SECONDS", 0.2)

    started = time.monotonic()
    info = asyncio.run(bgptools.network_info("1.1.1.1"))
    assert time.monotonic() - started < 2
    assert opened == [True]
    # The lookup degrades to empty details instead of raising or hanging.
    assert info["1.1.1.1"]["asn"] == ""


def test_whois_results_are_cached_per_address_and_expire(state, monkeypatch):
    calls = []

    async def fake_whois(targets):
        calls.append(list(targets))
        return "\n".join(
            f"64500 | {target} | 192.0.2.0/24 | AU | APNIC | 2020-01-01 | Example"
            for target in targets
        )

    monkeypatch.setattr(bgptools, "run_whois", fake_whois)

    first = asyncio.run(bgptools.network_info("1.1.1.1"))
    second = asyncio.run(bgptools.network_info("1.1.1.1", "8.8.8.8"))

    assert first["1.1.1.1"]["asn"] == "64500"
    assert second["1.1.1.1"] == first["1.1.1.1"]
    # The second call only asks for the address that was not cached.
    assert calls == [["1.1.1.1"], ["8.8.8.8"]]

    redis = state.redis
    ttl = redis.instance.ttl(redis.key(bgptools._cache_key("1.1.1.1")))
    assert 0 < ttl <= bgptools.CACHE_SECONDS


# --- RPKI ----------------------------------------------------------------------------


def test_rpki_results_are_cached_per_route_and_expire(state, monkeypatch):
    posts = []

    class FakeClient:
        def __init__(self, **_: t.Any) -> None:
            pass

        def __enter__(self):
            return self

        def __exit__(self, *_: t.Any) -> bool:
            return False

        def _post(self, endpoint, data):
            posts.append(data["query"])
            return {"data": {"validation": {"state": "Valid"}}}

    monkeypatch.setattr(rpki, "BaseExternal", FakeClient)

    assert rpki.rpki_state("10.1.1.0/24", 64500) == 1
    assert rpki.rpki_state("10.1.1.0/24", 64500) == 1
    assert len(posts) == 1

    # Dots in the prefix must not make two routes share a cache entry.
    assert rpki._cache_key("10.1.1.0/24@64500") != rpki._cache_key("10.1.0/24@64500")
    assert rpki.rpki_state("10.1.0.0/24", 64500) == 1
    assert len(posts) == 2

    redis = state.redis
    ttl = redis.instance.ttl(redis.key(rpki._cache_key("10.1.1.0/24@64500")))
    assert 0 < ttl <= rpki.CACHE_SECONDS


def test_rpki_errors_are_not_cached(state, monkeypatch):
    class FailingClient:
        def __init__(self, **_: t.Any) -> None:
            pass

        def __enter__(self):
            raise ExternalError(message="unreachable")

        def __exit__(self, *_: t.Any) -> bool:
            return False

    monkeypatch.setattr(rpki, "BaseExternal", FailingClient)
    assert rpki.rpki_state("192.0.2.0/24", 64500) == 3
    assert state.redis.get(rpki._cache_key("192.0.2.0/24@64500")) is None
