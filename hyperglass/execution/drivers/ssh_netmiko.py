"""Netmiko-Specific Classes & Utilities.

https://github.com/ktbyers/netmiko
"""

# Standard Library
import math
from typing import Iterable

# Third Party
import anyio
from netmiko import (  # type: ignore
    ConnectHandler,
    NetMikoTimeoutException,
    NetMikoAuthenticationException,
)

# Project
from hyperglass.log import log
from hyperglass.state import use_state
from hyperglass.exceptions.public import AuthError, DeviceTimeout, ResponseEmpty

# Local
from .ssh import SSHConnection

netmiko_device_globals = {
    # Netmiko doesn't currently handle Mikrotik echo verification well,
    # see ktbyers/netmiko#1600
    "mikrotik_routeros": {"global_cmd_verify": False},
    "mikrotik_switchos": {"global_cmd_verify": False},
}

# Per-platform `send_command` overrides. `read_timeout` values are clamped to
# the request budget at call time (see `_send_args`); the Arista value is a
# ceiling for deployments that raise `request_timeout` above the default.
netmiko_device_send_args = {
    "arista_eos": {"read_timeout": 120},
}

# Netmiko's own default for `send_command(read_timeout=...)`.
NETMIKO_DEFAULT_READ_TIMEOUT = 10


def _send_args(platform: str, request_timeout: float) -> dict:
    """Build `send_command` kwargs with `read_timeout` bounded by the request budget.

    `execution.main.execute` abandons the request after `request_timeout - 1`
    seconds. Any `read_timeout` beyond that only keeps the device SSH session
    open with no way to deliver the result, so cap it just inside the budget.
    """
    args = {**netmiko_device_send_args.get(platform, {})}
    budget = max(1, int(request_timeout) - 2)
    args["read_timeout"] = min(args.get("read_timeout", NETMIKO_DEFAULT_READ_TIMEOUT), budget)
    return args


class NetmikoConnection(SSHConnection):
    """Handle a device connection via Netmiko."""

    # Live Netmiko connection, set by the worker thread once established, so
    # the request's timeout path can tear the session down from the event loop.
    _connection = None
    _aborted = False

    def abort(self) -> None:
        """Close the device session from outside the worker thread.

        Called when the HTTP request times out. Closing the paramiko transport
        makes the worker thread's blocking read fail immediately, so the device
        SSH session is released now instead of when Netmiko's `read_timeout`
        expires. Safe to call before the connection exists: `_collect` checks
        `_aborted` after connecting and disconnects without sending commands.
        """
        self._aborted = True
        connection = self._connection
        if connection is None:
            return
        _log = log.bind(device=self.device.name)
        try:
            transport = getattr(connection, "remote_conn_pre", None)
            if transport is not None:
                transport.close()
            else:
                connection.disconnect()
            _log.debug("Aborted device session")
        except Exception as err:  # noqa: BLE001
            _log.bind(error=str(err)).warning("Failed to abort device session")

    async def collect(self, host: str = None, port: int = None) -> Iterable:
        """Connect directly to a device.

        Netmiko performs blocking, synchronous socket I/O. Running it directly
        on the ASGI event loop would stall every other in-flight request for the
        duration of the device interaction (up to the request timeout), so the
        work is offloaded to a worker thread. ``abandon_on_cancel=True`` lets the
        upstream timeout in ``execution.main.execute`` return promptly on
        expiry. The thread still runs until Netmiko's connection/read operations
        finish; ``session_timeout`` is a lock timeout, not a total deadline.
        """
        return await anyio.to_thread.run_sync(self._collect, host, port, abandon_on_cancel=True)

    def _collect(self, host: str = None, port: int = None) -> Iterable:
        """Perform the blocking Netmiko device interaction (worker thread)."""
        params = use_state("params")
        _log = log.bind(
            device=self.device.name,
            address=f"{host}:{port}",
            proxy=str(self.device.proxy.address) if self.device.proxy is not None else None,
        )

        _log.debug("Connecting to device")

        global_args = netmiko_device_globals.get(self.device.platform, {})

        send_args = _send_args(self.device.platform, params.request_timeout)

        driver_kwargs = {
            "host": host or self.device._target,
            "port": port or self.device.port,
            "device_type": self.device.get_device_type(),
            "username": self.device.credential.username,
            "global_delay_factor": 0.1,
            "timeout": math.floor(params.request_timeout * 1.25),
            "session_timeout": math.ceil(params.request_timeout - 1),
            **global_args,
            **self.device.driver_config,
        }

        if "_telnet" in self.device.platform:
            # Telnet devices with a low delay factor (default) tend to
            # throw login errors.
            driver_kwargs["global_delay_factor"] = 2

        if self.device.credential._method == "password":
            # Use password auth if no key is defined.
            driver_kwargs["password"] = self.device.credential.password.get_secret_value()
        else:
            # Otherwise, use key auth.
            driver_kwargs["use_keys"] = True
            driver_kwargs["key_file"] = self.device.credential.key
            if self.device.credential._method == "encrypted_key":
                # If the key is encrypted, use the password field as the
                # private key password.
                driver_kwargs["passphrase"] = self.device.credential.password.get_secret_value()

        try:
            nm_connect_direct = ConnectHandler(**driver_kwargs)
            self._connection = nm_connect_direct

            responses = ()

            try:
                if self._aborted:
                    # The request timed out while we were still connecting.
                    raise DeviceTimeout(
                        error=TimeoutError("Request timed out during connection"),
                        device=self.device,
                    )
                for query in self.query:
                    raw = nm_connect_direct.send_command(query, **send_args)
                    responses += (raw,)
            finally:
                self._connection = None
                nm_connect_direct.disconnect()

        except NetMikoTimeoutException as scrape_error:
            raise DeviceTimeout(error=scrape_error, device=self.device) from scrape_error

        except NetMikoAuthenticationException as auth_error:
            raise AuthError(error=auth_error, device=self.device) from auth_error

        if not responses:
            raise ResponseEmpty(query=self.query_data)

        return responses
