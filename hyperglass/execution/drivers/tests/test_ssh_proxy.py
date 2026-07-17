"""Tests for the SSH proxy (ProxyJump-equivalent) channel setup."""

# Standard Library
import typing as t

# Third Party
import pytest
import paramiko

# Project
from hyperglass.state import use_state
from hyperglass.models.directive import Directives
from hyperglass.models.config.params import Params
from hyperglass.models.config.devices import Device
from hyperglass.exceptions.public import AuthError, RestError, ScrapeError, DeviceTimeout

# Local
from ..ssh import SSHConnection
from ..ssh_netmiko import NetmikoConnection

if t.TYPE_CHECKING:
    # Project
    from hyperglass.state import HyperglassState

PROXY_ADDRESS = "203.0.113.1"
DEVICE_ADDRESS = "192.0.2.1"


@pytest.fixture
def state() -> t.Generator["HyperglassState", None, None]:
    """Initialize params state, required by `proxy_channel` and public errors."""
    _state = use_state()
    with _state.cache.pipeline() as pipeline:
        pipeline.set("params", Params())
        pipeline.set("directives", Directives.new())
    yield _state
    _state.clear()


def make_device(**overrides: t.Any) -> Device:
    """Build a device, optionally with proxy configuration."""
    config = {
        "name": "test1",
        "address": DEVICE_ADDRESS,
        "credential": {"username": "user", "password": "pass"},
        "platform": "juniper",
        **overrides,
    }
    return Device(**config)


def make_proxied_device(
    proxy_credential: t.Optional[t.Dict[str, t.Any]] = None, **proxy_overrides: t.Any
) -> Device:
    """Build a device behind an SSH proxy."""
    return make_device(
        proxy={
            "address": PROXY_ADDRESS,
            "credential": proxy_credential or {"username": "proxyuser", "password": "proxypass"},
            **proxy_overrides,
        }
    )


def make_connection(device: Device) -> SSHConnection:
    """Build an SSH connection without query construction.

    `proxy_channel` only requires `self.device`; bypassing `__init__` avoids
    needing directives/query state for these tests.
    """
    connection = NetmikoConnection.__new__(NetmikoConnection)
    connection.device = device
    return connection


def test_no_proxy_yields_none(state, fake_paramiko):
    connection = make_connection(make_device())
    with connection.proxy_channel() as sock:
        assert sock is None
    assert fake_paramiko["clients"] == []


def test_password_auth_opens_direct_tcpip_channel(state, fake_paramiko):
    connection = make_connection(make_proxied_device())

    with connection.proxy_channel() as sock:
        assert sock is not None

    (client,) = fake_paramiko["clients"]
    assert client.connect_kwargs["hostname"] == PROXY_ADDRESS
    assert client.connect_kwargs["port"] == 22
    assert client.connect_kwargs["username"] == "proxyuser"
    assert client.connect_kwargs["password"] == "proxypass"  # noqa: S105
    assert client.connect_kwargs["allow_agent"] is False
    assert client.connect_kwargs["look_for_keys"] is False
    assert client.open_channel_args["kind"] == "direct-tcpip"
    assert client.open_channel_args["dest_addr"] == (DEVICE_ADDRESS, 22)
    assert sock is client.channel
    assert client.closed is True

    expected_timeout = max(Params().request_timeout - 2, 1)
    assert client.connect_kwargs["timeout"] == expected_timeout
    assert client.connect_kwargs["banner_timeout"] == expected_timeout
    assert client.connect_kwargs["auth_timeout"] == expected_timeout
    # The channel open gets whatever budget the connect phases left over.
    assert 0 < client.open_channel_args["timeout"] <= expected_timeout


def test_key_auth(state, fake_paramiko, tmp_path):
    key_file = tmp_path / "proxy_key"
    key_file.write_text("fake key")
    connection = make_connection(
        make_proxied_device(proxy_credential={"username": "proxyuser", "key": str(key_file)})
    )

    with connection.proxy_channel():
        pass

    (client,) = fake_paramiko["clients"]
    assert client.connect_kwargs["key_filename"] == str(key_file)
    assert "password" not in client.connect_kwargs
    assert "passphrase" not in client.connect_kwargs


def test_encrypted_key_auth(state, fake_paramiko, tmp_path):
    key_file = tmp_path / "proxy_key"
    key_file.write_text("fake key")
    connection = make_connection(
        make_proxied_device(
            proxy_credential={
                "username": "proxyuser",
                "key": str(key_file),
                "password": "key passphrase",
            }
        )
    )

    with connection.proxy_channel():
        pass

    (client,) = fake_paramiko["clients"]
    assert client.connect_kwargs["key_filename"] == str(key_file)
    assert client.connect_kwargs["passphrase"] == "key passphrase"  # noqa: S105
    assert "password" not in client.connect_kwargs


def test_custom_proxy_port(state, fake_paramiko):
    connection = make_connection(make_proxied_device(port=2222))

    with connection.proxy_channel():
        pass

    (client,) = fake_paramiko["clients"]
    assert client.connect_kwargs["port"] == 2222


def test_host_key_unverified_by_default(state, fake_paramiko):
    connection = make_connection(make_proxied_device())

    with connection.proxy_channel():
        pass

    (client,) = fake_paramiko["clients"]
    assert isinstance(client.policy, paramiko.AutoAddPolicy)
    assert client.host_keys_file is None


def test_host_key_strictly_verified_with_known_hosts(state, fake_paramiko, tmp_path):
    known_hosts = tmp_path / "known_hosts"
    known_hosts.write_text("")
    connection = make_connection(make_proxied_device(known_hosts_file=str(known_hosts)))

    with connection.proxy_channel():
        pass

    (client,) = fake_paramiko["clients"]
    assert isinstance(client.policy, paramiko.RejectPolicy)
    assert client.host_keys_file == str(known_hosts)


def test_auth_failure_raises_auth_error(state, fake_paramiko):
    fake_paramiko["connect_exc"] = paramiko.AuthenticationException("denied")
    connection = make_connection(make_proxied_device())

    with pytest.raises(AuthError) as excinfo:
        with connection.proxy_channel():
            pass

    assert "SSH proxy" in str(excinfo.value)
    assert fake_paramiko["clients"][0].closed is True


def test_channel_rejection_raises_scrape_error(state, fake_paramiko):
    fake_paramiko["open_channel_exc"] = paramiko.ChannelException(1, "administratively prohibited")
    connection = make_connection(make_proxied_device())

    with pytest.raises(ScrapeError) as excinfo:
        with connection.proxy_channel():
            pass

    assert "SSH proxy" in str(excinfo.value)
    # The default connection_error template must render the device name, not
    # a literal '{device_name}' placeholder.
    assert str(excinfo.value).startswith("Error connecting to test1:")
    assert fake_paramiko["clients"][0].closed is True


def test_connect_timeout_raises_device_timeout(state, fake_paramiko):
    fake_paramiko["connect_exc"] = TimeoutError("timed out")
    connection = make_connection(make_proxied_device())

    with pytest.raises(DeviceTimeout):
        with connection.proxy_channel():
            pass

    assert fake_paramiko["clients"][0].closed is True


def test_channel_open_timeout_raises_device_timeout(state, fake_paramiko):
    # paramiko raises channel-open timeouts as a generic SSHException.
    fake_paramiko["open_channel_exc"] = paramiko.SSHException("Timeout opening channel.")
    connection = make_connection(make_proxied_device())

    with pytest.raises(DeviceTimeout):
        with connection.proxy_channel():
            pass

    assert fake_paramiko["clients"][0].closed is True


def test_host_key_rejection_raises_scrape_error(state, fake_paramiko):
    fake_paramiko["connect_exc"] = paramiko.SSHException(
        "Server '203.0.113.1' not found in known_hosts"
    )
    connection = make_connection(make_proxied_device())

    with pytest.raises(ScrapeError) as excinfo:
        with connection.proxy_channel():
            pass

    assert "SSH proxy" in str(excinfo.value)


def test_socket_error_raises_scrape_error(state, fake_paramiko):
    fake_paramiko["connect_exc"] = ConnectionRefusedError("connection refused")
    connection = make_connection(make_proxied_device())

    with pytest.raises(ScrapeError):
        with connection.proxy_channel():
            pass

    assert fake_paramiko["clients"][0].closed is True


def test_client_closed_when_body_raises(state, fake_paramiko):
    connection = make_connection(make_proxied_device())

    with pytest.raises(RuntimeError):
        with connection.proxy_channel():
            raise RuntimeError("driver blew up")

    assert fake_paramiko["clients"][0].closed is True


def test_public_error_does_not_leak_proxy_details(state, fake_paramiko):
    fake_paramiko["connect_exc"] = paramiko.AuthenticationException("denied")
    connection = make_connection(make_proxied_device())

    with pytest.raises(AuthError) as excinfo:
        with connection.proxy_channel():
            pass

    # Neither the proxy's credential nor its address may appear in the
    # user-facing message or keywords; hop attribution is text-only.
    assert "SSH proxy" in str(excinfo.value)
    assert PROXY_ADDRESS not in str(excinfo.value)
    keywords = excinfo.value.keywords
    assert not any(PROXY_ADDRESS in keyword for keyword in keywords)
    assert not any("proxyuser" in keyword for keyword in keywords)


def test_os_error_does_not_leak_key_path(state, fake_paramiko, tmp_path):
    key_file = tmp_path / "proxy_key"
    key_file.write_text("fake key")
    fake_paramiko["connect_exc"] = FileNotFoundError(2, "No such file or directory", str(key_file))
    connection = make_connection(
        make_proxied_device(proxy_credential={"username": "proxyuser", "key": str(key_file)})
    )

    with pytest.raises(ScrapeError) as excinfo:
        with connection.proxy_channel():
            pass

    assert "No such file or directory" in str(excinfo.value)
    assert str(tmp_path) not in str(excinfo.value)
    assert not any(str(tmp_path) in keyword for keyword in excinfo.value.keywords)


def test_auth_timeout_raises_device_timeout(state, fake_paramiko):
    # paramiko raises authentication-phase timeouts as AuthenticationException.
    fake_paramiko["connect_exc"] = paramiko.AuthenticationException("Authentication timeout.")
    connection = make_connection(make_proxied_device())

    with pytest.raises(DeviceTimeout):
        with connection.proxy_channel():
            pass


def test_banner_timeout_raises_device_timeout(state, fake_paramiko):
    # A bare socket.timeout stringifies to '', so paramiko's banner-timeout
    # message ends with 'banner'.
    fake_paramiko["connect_exc"] = paramiko.SSHException("Error reading SSH protocol banner")
    connection = make_connection(make_proxied_device())

    with pytest.raises(DeviceTimeout):
        with connection.proxy_channel():
            pass


def test_known_hosts_read_failure_raises_scrape_error(state, fake_paramiko, tmp_path, monkeypatch):
    known_hosts = tmp_path / "known_hosts"
    known_hosts.write_text("")
    connection = make_connection(make_proxied_device(known_hosts_file=str(known_hosts)))

    def broken_load_host_keys(self, filename):
        raise PermissionError(13, "Permission denied", filename)

    monkeypatch.setattr(paramiko.SSHClient, "load_host_keys", broken_load_host_keys)

    with pytest.raises(ScrapeError):
        with connection.proxy_channel():
            pass

    assert fake_paramiko["clients"][0].closed is True


def test_rest_error_renders_device_name(state):
    error = RestError(error=RuntimeError("api unreachable"), device=make_device())
    assert str(error).startswith("Error connecting to test1:")
    assert "{device_name}" not in str(error)
