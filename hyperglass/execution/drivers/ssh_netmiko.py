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
from netmiko.exceptions import ReadException  # type: ignore

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

netmiko_device_send_args = {
    "arista_eos": {"read_timeout": 120},
}


class NetmikoConnection(SSHConnection):
    """Handle a device connection via Netmiko."""

    async def collect(self) -> Iterable:
        """Connect to a device, optionally via its SSH proxy.

        Netmiko performs blocking, synchronous socket I/O. Running it directly
        on the ASGI event loop would stall every other in-flight request for the
        duration of the device interaction (up to the request timeout), so the
        work is offloaded to a worker thread. ``abandon_on_cancel=True`` lets the
        upstream timeout in ``execution.main.execute`` return promptly on
        expiry; the abandoned thread is bounded by the SSH proxy stage timeouts
        (when a proxy is configured) plus Netmiko's own ``timeout`` /
        ``session_timeout``.
        """
        return await anyio.to_thread.run_sync(self._collect, abandon_on_cancel=True)

    def _collect(self) -> Iterable:
        """Perform the blocking Netmiko device interaction (worker thread)."""
        params = use_state("params")
        _log = log.bind(
            device=self.device.name,
            address=f"{self.device._target}:{self.device.port}",
            proxy=str(self.device.proxy.address) if self.device.proxy is not None else None,
        )

        _log.debug("Connecting to device")

        global_args = netmiko_device_globals.get(self.device.platform, {})

        send_args = netmiko_device_send_args.get(self.device.platform, {})

        driver_kwargs = {
            "host": self.device._target,
            "port": self.device.port,
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

        with self.proxy_channel() as proxy_sock:
            if proxy_sock is not None:
                # Set after the `driver_config` spread so user-supplied driver
                # config cannot replace the proxy channel.
                driver_kwargs["sock"] = proxy_sock

            responses = self._run_queries(driver_kwargs, send_args)

        if not responses:
            raise ResponseEmpty(query=self.query_data)

        return responses

    def _run_queries(self, driver_kwargs: dict, send_args: dict) -> Iterable:
        """Run this connection's queries over a Netmiko session, always disconnecting."""
        session = None
        responses = ()

        try:
            session = ConnectHandler(**driver_kwargs)

            for query in self.query:
                raw = session.send_command(query, **send_args)
                responses += (raw,)

        except NetMikoTimeoutException as scrape_error:
            raise DeviceTimeout(error=scrape_error, device=self.device) from scrape_error

        except ReadException as read_error:
            # Netmiko raises `send_command` read timeouts as ReadTimeout
            # (a ReadException), not as NetMikoTimeoutException.
            raise DeviceTimeout(error=read_error, device=self.device) from read_error

        except NetMikoAuthenticationException as auth_error:
            raise AuthError(error=auth_error, device=self.device) from auth_error

        finally:
            if session is not None:
                try:
                    session.disconnect()
                except Exception:  # noqa: BLE001
                    # Never let disconnect cleanup mask the real error.
                    log.bind(device=self.device.name).debug("Error disconnecting from device")

        return responses
