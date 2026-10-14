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
    # Arista's 120s read_timeout is clamped to the request budget (90 - 2).
    assert all(
        call.kwargs == {"read_timeout": 88} for call in transport.send_command.call_args_list
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


def test_read_timeout_is_clamped_to_request_budget():
    assert ssh_netmiko._send_args("arista_eos", 90) == {"read_timeout": 88}
    # A deployment with a generous request_timeout keeps the Arista ceiling.
    assert ssh_netmiko._send_args("arista_eos", 300) == {"read_timeout": 120}
    # Other platforms keep Netmiko's default unless the budget is smaller.
    assert ssh_netmiko._send_args("cisco_ios", 90) == {"read_timeout": 10}
    assert ssh_netmiko._send_args("cisco_ios", 8) == {"read_timeout": 6}
    assert ssh_netmiko._send_args("cisco_ios", 1) == {"read_timeout": 1}


def test_abort_closes_live_transport(connection):
    driver, transport, _ = connection
    driver._connection = transport
    driver.abort()
    transport.remote_conn_pre.close.assert_called_once_with()
    assert driver._aborted is True


def test_abort_before_connection_is_noop_and_blocks_commands(connection):
    driver, transport, _ = connection
    driver.abort()  # nothing to close yet
    transport.remote_conn_pre.close.assert_not_called()
    # The request has already timed out by the time the connection comes up:
    # disconnect without sending any command.
    with pytest.raises(DeviceTimeout):
        driver._collect()
    transport.send_command.assert_not_called()
    transport.disconnect.assert_called_once_with()
    assert driver._connection is None


def test_abort_failure_is_swallowed(connection):
    driver, transport, _ = connection
    transport.remote_conn_pre.close.side_effect = OSError("already closed")
    driver._connection = transport
    driver.abort()  # must not raise


def test_connection_handle_is_cleared_after_collect(connection):
    driver, transport, _ = connection
    transport.send_command.side_effect = ["a", "b"]
    driver._collect()
    assert driver._connection is None
