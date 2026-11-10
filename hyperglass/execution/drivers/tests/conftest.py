"""Shared fixtures for SSH driver tests."""

# Standard Library
import typing as t

# Third Party
import pytest
import paramiko

# Project
from hyperglass.state.hooks import _use_state


@pytest.fixture(autouse=True)
def clear_state_cache() -> t.Generator[None, None, None]:
    """Clear the `use_state` lru_cache around each test.

    `use_state` caches the first value read for each state attribute for the
    life of the process; without clearing it, state written by this module's
    fixtures is invisible when other test modules populated the cache first,
    and state cached here would leak into later modules.
    """
    _use_state.cache_clear()
    yield
    _use_state.cache_clear()


class FakeChannel:
    """Stand-in for a paramiko Channel."""

    def __init__(self):
        self.closed = False

    def close(self):
        """Mark the channel closed."""
        self.closed = True


class FakeTransport:
    """Stand-in for a paramiko Transport that records channel requests."""

    def __init__(self, client: "FakeSSHClient", record: t.Dict[str, t.Any]):
        self._client = client
        self._record = record

    def open_channel(self, kind, dest_addr=None, src_addr=None, timeout=None):
        """Record channel arguments; return a fake channel or raise."""
        self._client.open_channel_args = {
            "kind": kind,
            "dest_addr": dest_addr,
            "src_addr": src_addr,
            "timeout": timeout,
        }
        if self._record["open_channel_exc"] is not None:
            raise self._record["open_channel_exc"]
        self._client.channel = FakeChannel()
        return self._client.channel


class FakeSSHClient:
    """Stand-in for paramiko.SSHClient that records interactions."""

    # Set by the `fake_paramiko` fixture before use.
    record: t.ClassVar[t.Dict[str, t.Any]] = {}

    def __init__(self):
        self.record["clients"].append(self)
        self.connect_kwargs = None
        self.closed = False
        self.policy = None
        self.host_keys_file = None
        self.channel = None
        self.open_channel_args = None

    def load_host_keys(self, filename):
        """Record the loaded known_hosts file."""
        self.host_keys_file = filename

    def set_missing_host_key_policy(self, policy):
        """Record the missing host key policy."""
        self.policy = policy

    def connect(self, **kwargs):
        """Record connection arguments; raise if configured to."""
        self.connect_kwargs = kwargs
        if self.record["connect_exc"] is not None:
            raise self.record["connect_exc"]

    def get_transport(self):
        """Return a fake transport bound to this client."""
        return FakeTransport(self, self.record)

    def close(self):
        """Mark the client closed."""
        self.closed = True


@pytest.fixture
def fake_paramiko(monkeypatch: pytest.MonkeyPatch) -> t.Dict[str, t.Any]:
    """Replace `paramiko.SSHClient` with a recording fake.

    The returned record exposes created clients and lets tests inject
    exceptions via `connect_exc` and `open_channel_exc`.
    """
    record: t.Dict[str, t.Any] = {"clients": [], "connect_exc": None, "open_channel_exc": None}
    monkeypatch.setattr(FakeSSHClient, "record", record)
    monkeypatch.setattr(paramiko, "SSHClient", FakeSSHClient)
    return record
