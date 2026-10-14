"""Validate SSH proxy configuration variables."""

# Standard Library
import typing as t
from ipaddress import IPv4Address, IPv6Address

# Third Party
from pydantic import FilePath, ValidationInfo, field_validator, model_validator

# Project
from hyperglass.log import log
from hyperglass.util import resolve_hostname
from hyperglass.exceptions.private import ConfigError

# Local
from ..main import HyperglassModel
from ..util import check_legacy_fields
from .credential import Credential


# Proxies for which the disabled-host-key-verification warning has been
# logged, keyed by `address:port`. Deduplicates the warning across devices
# sharing a proxy and across pydantic's repeated validation passes.
_HOST_KEY_WARNED: t.Set[str] = set()


class Proxy(HyperglassModel):
    """Validation model for per-proxy config in devices.yaml."""

    address: t.Union[IPv4Address, IPv6Address, str]
    port: int = 22
    credential: Credential
    platform: str = "linux_ssh"
    known_hosts_file: t.Optional[FilePath] = None

    def __init__(self: "Proxy", **kwargs: t.Any) -> None:
        """Check for legacy fields & convert host paths to container paths."""
        kwargs = check_legacy_fields(model="Proxy", data=kwargs)
        super().__init__(**self.convert_paths(kwargs))

    @property
    def _target(self):
        return str(self.address)

    @field_validator("address")
    def validate_address(cls, value):
        """Ensure a hostname is resolvable."""

        if not isinstance(value, (IPv4Address, IPv6Address)):
            if not any(resolve_hostname(value)):
                raise ConfigError(
                    "Proxy '{a}' is not resolvable.",
                    a=value,
                )
        return value

    @field_validator("platform", mode="before")
    def validate_type(cls: "Proxy", value: t.Any, info: ValidationInfo) -> str:
        """Validate device type."""

        if value != "linux_ssh":
            raise ConfigError(
                "Proxy '{a}' uses platform '{p}', which is unsupported. "
                "Proxy platform must be 'linux_ssh'.",
                a=info.data.get("address"),
                p=value,
            )
        return value

    @model_validator(mode="after")
    def warn_unverified_host_key(self) -> "Proxy":
        """Warn, once per unique proxy, when its host key will not be verified."""
        key = f"{self.address}:{self.port}"
        if self.known_hosts_file is None and key not in _HOST_KEY_WARNED:
            _HOST_KEY_WARNED.add(key)
            log.bind(proxy=str(self.address)).warning(
                "Proxy host key verification is disabled. Set 'known_hosts_file' "
                "on the proxy to enable it"
            )
        return self
