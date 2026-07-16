"""Common Classes or Utilities for SSH Drivers."""

# Standard Library
import typing as t
from contextlib import contextmanager

# Third Party
import paramiko

# Project
from hyperglass.log import log
from hyperglass.state import use_state
from hyperglass.exceptions.public import AuthError, ScrapeError, DeviceTimeout

# Local
from ._common import Connection

if t.TYPE_CHECKING:
    # Project
    from hyperglass.models.config.proxy import Proxy


def _proxy_error(proxy: "Proxy", error: BaseException) -> str:
    """Attribute an error to the SSH proxy hop, not the device."""
    return f"Error via SSH proxy {proxy.address}:{proxy.port}: {error}"


def _proxy_connect_kwargs(proxy: "Proxy", timeout: int) -> t.Dict[str, t.Any]:
    """Build paramiko connection arguments from a proxy's configuration."""
    kwargs: t.Dict[str, t.Any] = {
        "hostname": proxy._target,
        "port": proxy.port,
        "username": proxy.credential.username,
        "timeout": timeout,
        "banner_timeout": timeout,
        "auth_timeout": timeout,
        # Only ever offer the configured credential to the proxy — never
        # SSH agent keys or keys found in ~/.ssh.
        "allow_agent": False,
        "look_for_keys": False,
    }
    if proxy.credential._method == "password":
        kwargs["password"] = proxy.credential.password.get_secret_value()
    else:
        kwargs["key_filename"] = proxy.credential.key.as_posix()
        if proxy.credential._method == "encrypted_key":
            kwargs["passphrase"] = proxy.credential.password.get_secret_value()
    return kwargs


class SSHConnection(Connection):
    """Base class for SSH drivers."""

    @contextmanager
    def proxy_channel(self) -> t.Iterator[t.Optional[paramiko.Channel]]:
        """Open a channel to the device through its SSH proxy, like OpenSSH's ProxyJump.

        Connects to the device's configured proxy (bastion/jump server) and
        opens a ``direct-tcpip`` channel to the device, which the SSH driver
        uses as its transport socket. Yields ``None`` when the device has no
        proxy configured.

        Performs blocking network I/O; must only be called from a worker
        thread, never the event loop.
        """
        proxy = self.device.proxy

        if proxy is None:
            yield None
            return

        params = use_state("params")
        # Keep each stage of the proxy connection within the overall request
        # budget, equivalent to the previous tunnel's `gateway_timeout`.
        timeout = max(params.request_timeout - 2, 1)
        _log = log.bind(device=self.device.name, proxy=str(proxy.address))

        client = paramiko.SSHClient()
        if proxy.known_hosts_file is not None:
            client.load_host_keys(proxy.known_hosts_file.as_posix())
            client.set_missing_host_key_policy(paramiko.RejectPolicy())
        else:
            # Matches the historical behavior of the vendored sshtunnel-based
            # proxy, which never verified the proxy's host key. Opt in to
            # verification by setting `known_hosts_file` on the proxy.
            client.set_missing_host_key_policy(paramiko.AutoAddPolicy())  # noqa: S507

        try:
            try:
                client.connect(**_proxy_connect_kwargs(proxy, timeout))
                channel = client.get_transport().open_channel(
                    "direct-tcpip",
                    dest_addr=(self.device._target, self.device.port),
                    src_addr=("", 0),
                    timeout=timeout,
                )
            except paramiko.AuthenticationException as auth_error:
                _log.error("Authentication to SSH proxy failed")
                raise AuthError(
                    error=_proxy_error(proxy, auth_error), device=self.device
                ) from auth_error
            except paramiko.ChannelException as channel_error:
                # The proxy refused or failed to open a connection to the device.
                _log.error("SSH proxy could not open a connection to the device")
                raise ScrapeError(
                    error=_proxy_error(proxy, channel_error), device=self.device
                ) from channel_error
            except TimeoutError as timeout_error:
                _log.error("Timed out connecting to SSH proxy")
                raise DeviceTimeout(
                    error=_proxy_error(proxy, timeout_error), device=self.device
                ) from timeout_error
            except paramiko.SSHException as ssh_error:
                # Covers host key verification failures, transport errors, and
                # channel-open timeouts (which paramiko raises as SSHException).
                if "timeout" in str(ssh_error).lower():
                    _log.error("Timed out opening a channel through SSH proxy")
                    raise DeviceTimeout(
                        error=_proxy_error(proxy, ssh_error), device=self.device
                    ) from ssh_error
                _log.error("Failed to connect to device via SSH proxy")
                raise ScrapeError(
                    error=_proxy_error(proxy, ssh_error), device=self.device
                ) from ssh_error
            except OSError as os_error:
                _log.error("Failed to connect to SSH proxy")
                raise ScrapeError(
                    error=_proxy_error(proxy, os_error), device=self.device
                ) from os_error
            yield channel
        finally:
            # Closing the client closes its transport and any open channels.
            client.close()
