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


class Proxy(HyperglassModel):
    """Validation model for per-proxy config in devices.yaml."""

    address: t.Union[IPv4Address, IPv6Address, str]
    port: int = 22
    credential: Credential
    platform: str = "linux_ssh"
    known_hosts_file: t.Optional[FilePath] = None

    def __init__(self: "Proxy", **kwargs: t.Any) -> None:
        """Check for legacy fields."""
        kwargs = check_legacy_fields(model="Proxy", data=kwargs)
        super().__init__(**kwargs)

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
        """Warn when the proxy's host key will not be verified."""
        if self.known_hosts_file is None:
            log.bind(proxy=str(self.address)).warning(
                "Proxy host key verification is disabled. Set 'known_hosts_file' "
                "on the proxy to enable it"
            )
        return self
