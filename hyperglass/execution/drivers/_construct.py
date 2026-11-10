"""Construct SSH command/API parameters from validated query data.

Accepts filtered & validated input from execute.py, constructs SSH
command for Netmiko library or API call parameters for supported
hyperglass API modules.
"""

# Standard Library
import re
import json as _json
import typing as t
import ipaddress

# Project
from hyperglass.log import log
from hyperglass.util import get_fmt_keys
from hyperglass.constants import (
    TRANSPORT_REST,
    SHELL_PLATFORMS,
    TARGET_FORMAT_SPACE,
    canonical_ip_target,
    quote_shell_command,
    ip_target_has_zone_or_whitespace,
    target_contains_forbidden_content,
)
from hyperglass.exceptions.public import InputInvalid
from hyperglass.exceptions.private import ConfigError

if t.TYPE_CHECKING:
    # Third Party
    from loguru import Logger

    # Project
    from hyperglass.models.api.query import Query
    from hyperglass.models.directive import Directive
    from hyperglass.models.config.devices import Device

FormatterCallback = t.Callable[[str], t.Union[t.List[str], str]]

# Final, post-formatter defense before a target is interpolated into a device
# command. The same forbidden-content check runs at the type-level boundary in
# `models.api.query`; running it again here means a regression in either the
# QueryTarget constraint or a custom directive's regex still cannot reach
# `send_command`. IP targets are canonicalised (and zoned addresses rejected)
# so a scope id cannot add extra CLI words. Shell platforms then word-quote
# the command. The forbidden-content denylist rejects `$(` / `${` before that.


class Construct:
    """Construct SSH commands/REST API parameters from validated query data."""

    directive: "Directive"
    device: "Device"
    query: "Query"
    transport: str
    target: str
    _log: "Logger"

    def __init__(self, device: "Device", query: "Query"):
        """Initialize command construction."""
        self._log = log.bind(type=query.query_type, target=query.query_target)
        self._log.debug("Constructing query")
        self.query = query
        self.device = device
        self.target = self.query.query_target
        self.directive = query.directive

        # Set transport method based on NOS type
        self.transport = "scrape"
        if self.device.platform in TRANSPORT_REST:
            self.transport = "rest"

        # Remove slashes from target for required platforms
        if self.device.platform in TARGET_FORMAT_SPACE:
            self.target = re.sub(r"\/", r" ", str(self.query.query_target))

        with Formatter(self.query) as formatter:
            self.target = formatter(self.prepare_target())

    def prepare_target(self) -> t.Union[t.List[str], str]:
        """Format the query target based on directive parameters."""
        if isinstance(self.query.query_target, t.List):
            # Directive can accept multiple values in a single command.
            if self.directive.multiple:
                return self.directive.multiple_separator.join(self.query.query_target)
            # Target is an array of one, return single item.
            if len(self.query.query_target) == 1:
                return self.query.query_target[0]
            # Directive commands should be run once for each item in the target.

        return self.query.query_target

    def json(self, afi):
        """Return JSON version of validated query for REST devices."""
        self._log.debug("Building JSON query")
        return _json.dumps(
            {
                "query_type": self.query.query_type,
                "vrf": self.query.query_vrf.name,
                "afi": afi.protocol,
                "source": str(afi.source_address),
                "target": str(self.target),
            }
        )

    def _resolved_target(self) -> str:
        """Return the target string that may be interpolated into a command.

        Forbidden characters are rejected on the raw value. A string that
        parses as an IP is replaced with its canonical form so a raw zone id
        is never copied into the command; zoned or whitespace IP targets are
        rejected instead of being queried under the stripped address.
        """
        raw = self.target if isinstance(self.target, str) else str(self.target)
        if target_contains_forbidden_content(raw):
            raise InputInvalid(
                error="Target contains disallowed character(s)",
                target=raw,
            )
        if not isinstance(self.target, str):
            return raw

        canonical = canonical_ip_target(self.target)
        if canonical is None:
            return raw
        if ip_target_has_zone_or_whitespace(self.target):
            raise InputInvalid(
                error="IP target contains disallowed character(s)",
                target=self.target,
            )
        return canonical

    def format(self, command: str) -> str:
        """Return formatted command for 'Scrape' endpoints (SSH)."""
        keys = get_fmt_keys(command)
        attrs = {k: v for k, v in self.device.attrs.items() if k in keys}
        for key in [k for k in keys if k != "target" and k != "mask"]:
            if key not in attrs:
                raise ConfigError(
                    ("Command '{c}' has attribute '{k}', which is missing from device '{d}'"),
                    level="danger",
                    c=self.directive.name,
                    k=key,
                    d=self.device.name,
                )

        mask = ipaddress.ip_address("255.255.255.255")
        try:
            network = ipaddress.ip_network(self.target)
            if network.version == 4 and network.network_address != network.broadcast_address:
                # Network is an IPv4 network with more than one host.
                mask = network.netmask
        except ValueError:
            pass

        target_for_cmd = self._resolved_target()
        fmt = {"target": target_for_cmd, "mask": mask, **attrs}

        # Shell-backed NOS, including VyOS vbash and device platforms ``linux``
        # / ``linux_ssh``: word-quote the template so the target stays one
        # literal argument. Single quotes neutralize `$()`, `${}`, quotes,
        # spaces, and globs. A template operator is a config error; word-quoting
        # would otherwise turn it into a literal argument.
        if self._command_is_shell_backed():
            try:
                return quote_shell_command(command, **fmt)
            except ValueError as err:
                raise ConfigError(
                    "Command '{c}' on device '{d}' is not a word-quoted shell template ({reason})",
                    level="danger",
                    c=self.directive.name,
                    d=self.device.name,
                    reason=err,
                ) from err

        return command.format(**fmt)

    def _command_is_shell_backed(self) -> bool:
        """Return True when this device's command string is parsed by a shell.

        Platform names in ``SHELL_PLATFORMS`` cover the builtin NOS set and the
        generic ``linux`` / ``linux_ssh`` / ``vyos`` device types. A device
        object that reports one of those Netmiko device types is included even
        when the platform string is not itself in the set.
        """
        platform = getattr(self.device, "platform", None)
        if platform in SHELL_PLATFORMS:
            return True
        get_device_type = getattr(self.device, "get_device_type", None)
        if not callable(get_device_type):
            return False
        return get_device_type() in {"linux", "linux_ssh", "vyos"}

    def queries(self):
        """Return queries for each enabled AFI."""
        query = []

        rules = [r for r in self.directive.rules if r._passed is True]
        if len(rules) < 1:
            raise InputInvalid(
                error="No validation rules matched target '{target}'",
                target=self.query.query_target,
            )

        for rule in [r for r in self.directive.rules if r._passed is True]:
            for command in rule.commands:
                query.append(self.format(command))
        self._log.bind(constructed_query=query).debug("Constructed query")
        return query


class Formatter:
    """Modify query target based on the device's NOS requirements and the query type."""

    def __init__(self, query: "Query") -> None:
        """Initialize target formatting."""
        self.query = query
        self.platform = query.device.platform
        self.query_type = query.query_type

    def __enter__(self):
        """Get the relevant formatter."""
        return self._get_formatter()

    def __exit__(self, exc_type, exc_value, exc_traceback):
        """Handle context exit."""
        if exc_type is not None:
            log.error(exc_traceback)
        pass

    def _get_formatter(self):
        if self.platform in ("juniper", "juniper_junos"):
            if self.query_type == "bgp_aspath":
                return self._with_formatter(self._juniper_bgp_aspath)
        if self.platform in ("bird", "bird_ssh"):
            if self.query_type == "bgp_aspath":
                return self._with_formatter(self._bird_bgp_aspath)
            if self.query_type == "bgp_community":
                return self._with_formatter(self._bird_bgp_community)
        return self._with_formatter(self._default)

    def _default(self, target: str) -> str:
        """Don't format targets by default."""
        return target

    def _with_formatter(self, formatter: t.Callable[[str], str]) -> FormatterCallback:
        result: FormatterCallback
        if isinstance(self.query.query_target, t.List):
            result = lambda s: [formatter(i) for i in s]
        result = lambda s: formatter(s)
        return result

    def _juniper_bgp_aspath(self, target: str) -> str:
        """Convert from Cisco AS_PATH format to Juniper format."""
        query = str(target)
        asns = re.findall(r"\d+", query)
        was_modified = False

        if bool(re.match(r"^\_", query)):
            # Replace `_65000` with `.* 65000`
            asns.insert(0, r".*")
            was_modified = True

        if bool(re.match(r".*(\_)$", query)):
            # Replace `65000_` with `65000 .*`
            asns.append(r".*")
            was_modified = True

        if was_modified:
            modified = " ".join(asns)
            log.bind(original=target, modified=modified).debug("Modified target")
            return modified

        return query

    def _bird_bgp_aspath(self, target: str) -> str:
        """Convert from Cisco AS_PATH format to BIRD format."""

        # Extract ASNs from query target string
        asns = re.findall(r"\d+", target)
        was_modified = False

        if bool(re.match(r"^\_", target)):
            # Replace `_65000` with `.* 65000`
            asns.insert(0, "*")
            was_modified = True

        if bool(re.match(r".*(\_)$", target)):
            # Replace `65000_` with `65000 .*`
            asns.append("*")
            was_modified = True

        asns.insert(0, "[=")
        asns.append("=]")

        result = " ".join(asns)

        if was_modified:
            log.bind(original=target, modified=result).debug("Modified target")

        return result

    def _bird_bgp_community(self, target: str) -> str:
        """Convert from standard community format to BIRD format."""
        parts = target.split(":")
        return f"({','.join(parts)})"
