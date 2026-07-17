"""Tests for the Netmiko driver's SSH proxy wiring."""

# Standard Library
import typing as t

# Third Party
import pytest
from netmiko.exceptions import ReadTimeout  # type: ignore

# Project
from hyperglass.state import use_state
from hyperglass.models.api import Query
from hyperglass.configuration import init_ui_params
from hyperglass.models.directive import Directives
from hyperglass.models.config.params import Params
from hyperglass.models.config.devices import Devices
from hyperglass.exceptions.public import DeviceTimeout

# Local
from .. import ssh_netmiko
from ..ssh_netmiko import NetmikoConnection

if t.TYPE_CHECKING:
    # Project
    from hyperglass.state import HyperglassState

DEVICE_ADDRESS = "192.0.2.1"
PROXY_ADDRESS = "203.0.113.1"


@pytest.fixture
def state() -> t.Generator["HyperglassState", None, None]:
    """Initialize state with a direct device and a proxied device."""
    _state = use_state()
    _params = Params()
    _directives = Directives.new(
        {
            "juniper_bgp_route": {
                "name": "BGP Route",
                "rules": [
                    {
                        "condition": "0.0.0.0/0",
                        "ge": 8,
                        "le": 32,
                        "command": "show route protocol bgp table inet.0 {target} detail",
                    }
                ],
                "field": {"description": "IP Address or Prefix"},
            }
        }
    )

    with _state.cache.pipeline() as pipeline:
        pipeline.set("params", _params)
        pipeline.set("directives", _directives)

    common = {
        "credential": {"username": "user", "password": "pass"},
        "platform": "juniper",
        "attrs": {"source4": "192.0.2.254", "source6": "2001:db8::1"},
        "directives": ["juniper_bgp_route"],
    }
    _devices = Devices(
        {"name": "direct1", "address": DEVICE_ADDRESS, **common},
        {
            "name": "proxied1",
            "address": DEVICE_ADDRESS,
            "proxy": {
                "address": PROXY_ADDRESS,
                "credential": {"username": "proxyuser", "password": "proxypass"},
            },
            **common,
        },
    )
    ui_params = init_ui_params(params=_params, devices=_devices)

    with _state.cache.pipeline() as pipeline:
        pipeline.set("devices", _devices)
        pipeline.set("ui_params", ui_params)

    yield _state
    _state.clear()


@pytest.fixture
def fake_netmiko(monkeypatch: pytest.MonkeyPatch) -> t.Dict[str, t.Any]:
    """Replace Netmiko's ConnectHandler with a recording fake.

    Set `record["send_exc"]` to make `send_command` raise.
    """
    record: t.Dict[str, t.Any] = {"send_exc": None, "disconnected": False}

    class FakeNetmikoSession:
        def __init__(self, **kwargs):
            record["kwargs"] = kwargs

        def send_command(self, command, **kwargs):
            if record["send_exc"] is not None:
                raise record["send_exc"]
            return f"output: {command}"

        def disconnect(self):
            record["disconnected"] = True

    monkeypatch.setattr(ssh_netmiko, "ConnectHandler", FakeNetmikoSession)
    return record


def make_query(device_name: str) -> Query:
    return Query(
        queryLocation=device_name,
        queryTarget="192.0.2.0/24",
        queryType="juniper_bgp_route",
    )


def test_collect_via_proxy_passes_channel_as_sock(state, fake_paramiko, fake_netmiko):
    device = state.devices["proxied1"]
    connection = NetmikoConnection(device, make_query("proxied1"))

    responses = connection._collect()

    assert len(responses) == len(connection.query)
    (client,) = fake_paramiko["clients"]
    assert fake_netmiko["kwargs"]["sock"] is client.channel
    # The device connection targets the device itself, not a local forward.
    assert fake_netmiko["kwargs"]["host"] == DEVICE_ADDRESS
    assert fake_netmiko["kwargs"]["port"] == 22
    assert fake_netmiko["disconnected"] is True
    # The proxy client is closed once collection is complete.
    assert client.closed is True


def test_collect_without_proxy_connects_directly(state, fake_paramiko, fake_netmiko):
    device = state.devices["direct1"]
    connection = NetmikoConnection(device, make_query("direct1"))

    responses = connection._collect()

    assert len(responses) == len(connection.query)
    assert "sock" not in fake_netmiko["kwargs"]
    assert fake_netmiko["kwargs"]["host"] == DEVICE_ADDRESS
    assert fake_paramiko["clients"] == []


def test_driver_config_cannot_override_sock(state, fake_paramiko, fake_netmiko):
    device = state.devices["proxied1"]
    # Simulate a user-supplied `driver_config` attempting to set `sock`.
    device.driver_config["sock"] = "user-value"
    connection = NetmikoConnection(device, make_query("proxied1"))

    connection._collect()

    (client,) = fake_paramiko["clients"]
    assert fake_netmiko["kwargs"]["sock"] is client.channel


def test_read_timeout_classified_and_session_disconnected(state, fake_paramiko, fake_netmiko):
    """Netmiko raises send_command read timeouts as ReadTimeout, not NetmikoTimeoutException."""
    fake_netmiko["send_exc"] = ReadTimeout("Pattern not detected")
    device = state.devices["proxied1"]
    connection = NetmikoConnection(device, make_query("proxied1"))

    with pytest.raises(DeviceTimeout):
        connection._collect()

    # The device session is disconnected and the proxy client closed even on
    # failure paths.
    assert fake_netmiko["disconnected"] is True
    assert fake_paramiko["clients"][0].closed is True


def test_session_disconnected_on_success(state, fake_paramiko, fake_netmiko):
    device = state.devices["direct1"]
    connection = NetmikoConnection(device, make_query("direct1"))

    connection._collect()

    assert fake_netmiko["disconnected"] is True
