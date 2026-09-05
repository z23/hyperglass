"""Established SSH sessions must close even when a command fails."""

# Standard Library
from types import SimpleNamespace
from unittest.mock import Mock

# Third Party
import pytest
from pydantic import SecretStr
from netmiko.exceptions import ReadTimeout, NetmikoTimeoutException

# Project
from hyperglass.execution.drivers import ssh_netmiko
from hyperglass.exceptions.public import DeviceTimeout, ResponseEmpty
from hyperglass.models.config.messages import Messages


@pytest.fixture
def connection(monkeypatch):
    driver = object.__new__(ssh_netmiko.NetmikoConnection)
    driver.device = SimpleNamespace(
        name="Arista test",
        proxy=None,
        platform="arista_eos",
        _target="192.0.2.1",
        port=22,
        get_device_type=lambda: "arista_eos",
        driver_config={},
        credential=SimpleNamespace(_method="password", username="test", password=SecretStr("test")),
    )
    driver.query = ("show ip bgp 8.8.8.8", "show ipv6 bgp 2001:4860::/32")
    driver.query_data = SimpleNamespace(
        query_type="route", query_target="8.8.8.8", device=driver.device
    )
    params = SimpleNamespace(request_timeout=90, messages=Messages())
    monkeypatch.setattr(ssh_netmiko, "use_state", lambda key: params)
    monkeypatch.setattr("hyperglass.state.use_state", lambda key: params)
    transport = Mock()
    factory = Mock(return_value=transport)
    monkeypatch.setattr(ssh_netmiko, "ConnectHandler", factory)
    return driver, transport, factory


def test_success_preserves_arista_commands_and_disconnects(connection):
    driver, transport, factory = connection
    transport.send_command.side_effect = ["IPv4 result", "IPv6 result"]
    assert driver._collect() == ("IPv4 result", "IPv6 result")
    assert [call.args[0] for call in transport.send_command.call_args_list] == list(driver.query)
    assert all(
        call.kwargs == {"read_timeout": 120} for call in transport.send_command.call_args_list
    )
    assert factory.call_args.kwargs["device_type"] == "arista_eos"
    transport.disconnect.assert_called_once_with()


@pytest.mark.parametrize("error", [RuntimeError("failed"), ReadTimeout("read failed")])
@pytest.mark.parametrize("failed_command", [0, 1])
def test_command_errors_always_disconnect(connection, error, failed_command):
    driver, transport, _ = connection
    transport.send_command.side_effect = ["result"] * failed_command + [error]
    with pytest.raises(type(error)):
        driver._collect()
    transport.disconnect.assert_called_once_with()


def test_timeout_is_still_mapped_and_session_closed(connection):
    driver, transport, _ = connection
    transport.send_command.side_effect = NetmikoTimeoutException("timed out")
    with pytest.raises(DeviceTimeout):
        driver._collect()
    transport.disconnect.assert_called_once_with()


def test_failed_connection_does_not_disconnect_uninitialized_transport(connection):
    driver, transport, factory = connection
    factory.side_effect = NetmikoTimeoutException("connect failed")
    with pytest.raises(DeviceTimeout):
        driver._collect()
    transport.disconnect.assert_not_called()


def test_empty_command_list_still_disconnects(connection):
    driver, transport, _ = connection
    driver.query = ()
    with pytest.raises(ResponseEmpty):
        driver._collect()
    transport.disconnect.assert_called_once_with()
