"""Constant definitions used throughout the application."""

# Standard Library
import shlex
import typing as t
import ipaddress
from datetime import datetime

__name__ = "hyperglass"
__version__ = "2.0.4"
__author__ = "Matt Love"
__copyright__ = f"Copyright {datetime.now().year} Matthew Love"
__license__ = "BSD 3-Clause Clear License"

METADATA = (__name__, __version__, __author__, __copyright__, __license__)

MIN_PYTHON_VERSION = (3, 8)

MIN_NODE_VERSION = 18

TARGET_FORMAT_SPACE = ("huawei", "huawei_vrpv8")

TARGET_JUNIPER_ASPATH = ("juniper", "juniper_junos")

SUPPORTED_STRUCTURED_OUTPUT = ("frr", "juniper", "arista_eos")

CONFIG_EXTENSIONS = ("py", "yaml", "yml", "json", "toml")

STATUS_CODE_MAP = {"warning": 400, "error": 400, "danger": 500}

DNS_OVER_HTTPS = {
    "google": "https://dns.google/resolve",
    "cloudflare": "https://cloudflare-dns.com/dns-query",
}

PARSED_RESPONSE_FIELDS = (
    ("Prefix", "prefix", "left"),
    ("Active", "active", None),
    ("RPKI State", "rpki_state", "center"),
    ("AS Path", "as_path", "left"),
    ("Next Hop", "next_hop", "left"),
    ("Origin", "source_as", None),
    ("Weight", "weight", "center"),
    ("Local Preference", "local_preference", "center"),
    ("MED", "med", "center"),
    ("Communities", "communities", "center"),
    ("Originator", "source_rid", "right"),
    ("Peer", "peer_rid", "right"),
    ("Age", "age", "right"),
)

SUPPORTED_QUERY_FIELDS = ("query_location", "query_type", "query_target", "query_vrf")
SUPPORTED_QUERY_TYPES = (
    "bgp_route",
    "bgp_community",
    "bgp_aspath",
    "ping",
    "traceroute",
)

FUNC_COLOR_MAP = {
    "primary": "cyan",
    "secondary": "blue",
    "success": "green",
    "warning": "yellow",
    "error": "orange",
    "danger": "red",
}

TRANSPORT_REST = ("frr_legacy", "bird_legacy")

SCRAPE_HELPERS = {
    "arista": "arista_eos",
    "ios": "cisco_ios",
    "juniper_junos": "juniper",
    "junos": "juniper",
    "mikrotik": "mikrotik_routeros",
    "tsnr": "tnsr",
}

DRIVER_MAP = {
    "bird": "netmiko",
    "frr": "netmiko",
    "openbgpd": "netmiko",
    "http": "hyperglass_http_client",
}

LINUX_PLATFORMS = (
    "frr",
    "bird",
    "openbgpd",
)

# Platforms whose command string is parsed by a POSIX shell (Netmiko
# ``linux_ssh`` for FRR/BIRD/OpenBGPD, and TNSR's ``dataplane shell``).
# Targets on these platforms are interpolated as one ``shlex.quote``d word.
SHELL_PLATFORMS = LINUX_PLATFORMS + ("tnsr",)

# Characters that must never appear in a query target. Used at two points in
# the request pipeline (once at the type/validation boundary in
# `models.api.query`, again at the device-transport boundary in
# `execution.drivers._construct`) so a regression in either layer cannot let
# a CLI/shell metacharacter reach a device.
#
# Lone `$`, `(`, and `)` are intentionally *not* listed here: they are
# legitimate in BGP AS-path regular expressions (end anchors, groups). Shell
# command/parameter substitution is blocked separately via
# `FORBIDDEN_TARGET_SUBSTRINGS` (see `target_contains_forbidden_content`).
FORBIDDEN_TARGET_CHARS = frozenset(
    "\x00\x01\x02\x03\x04\x05\x06\x07\x08\t\n\x0b\x0c\r\x0e\x0f"
    "\x10\x11\x12\x13\x14\x15\x16\x17\x18\x19\x1a\x1b\x1c\x1d\x1e\x1f"
    "\x7f"  # DEL
    ";|&`<>\"\\"
)

# Multi-character sequences that are never legitimate looking-glass input.
# `$(...)` / `${...}` enable unauthenticated RCE on linux_ssh platforms
# (FRR/BIRD/OpenBGPD) where Netmiko delivers the command to a bash login shell
# and built-in directives interpolate `{target}` inside double quotes
# (`vtysh -c "… {target}"`), where unescaped `$` still expands.
FORBIDDEN_TARGET_SUBSTRINGS = ("$(", "${")


def target_contains_forbidden_content(value: str) -> bool:
    """Return True if `value` contains a forbidden char or shell-substitution sequence."""
    if any(c in FORBIDDEN_TARGET_CHARS for c in value):
        return True
    return any(seq in value for seq in FORBIDDEN_TARGET_SUBSTRINGS)


def shell_escape_linux_target(value: str) -> str:
    r"""Escape a target for interpolation inside double quotes on a Linux shell.

    Netmiko uses ``device_type=linux_ssh`` for FRR/BIRD/OpenBGPD and sends the
    full command string to a bash login shell. Built-in directives wrap
    ``{target}`` in double quotes, where unescaped ``$`` and backticks still
    expand. Escaping backslash, ``$``, backtick, and ``"`` makes bash pass the
    literal target through to the tool (so a legitimate AS-path anchor like
    ``^65000$`` reaches vtysh as ``^65000$``, while ``$(reboot)`` becomes inert
    text).

    ``SHELL_PLATFORMS`` do not use this escape on the rendered command: those
    commands are rebuilt with ``quote_shell_command``, and a backslash inside
    the resulting single quotes would keep a literal ``\\`` in front of an
    AS-path ``$``. This helper remains the double-quoted interpolation defense
    for any other Linux command line.

    Call only for ``LINUX_PLATFORMS``. Pure CLI NOS (Arista, Cisco, Juniper, …)
    do not evaluate shell metacharacters and must receive the target verbatim.
    """
    return (
        value.replace("\\", "\\\\")
        .replace("`", "\\`")
        .replace("$", "\\$")
        .replace('"', '\\"')
    )


def ip_target_has_zone_or_whitespace(value: str) -> bool:
    """Return True if an IP target contains an IPv6 zone id or any whitespace.

    ``ipaddress`` accepts ``address%zone`` and stores the zone text verbatim,
    including spaces (``2001:db8::1%x foo``). Stringifying that object keeps
    the extra word, which then lands on an EOS/Cisco CLI line or an unquoted
    ``ping`` argument. Looking-glass IP targets do not use zone ids.
    """
    return "%" in value or any(character.isspace() for character in value)


def canonical_ip_target(value: str) -> t.Optional[str]:
    """Return a scope-free canonical IP or prefix, or None when `value` is not an IP.

    Host addresses stay without a prefix length (``192.0.2.1``, not
    ``192.0.2.1/32``). An explicit prefix keeps its length. An IPv6 zone id is
    ignored so only the address bytes are returned; callers still reject zoned
    input rather than querying the stripped address.
    """
    if not isinstance(value, str) or value == "":
        return None

    address_text = value.split("%", 1)[0]
    head, slash, prefixlen = address_text.partition("/")
    try:
        if slash:
            if prefixlen == "":
                return None
            network = ipaddress.ip_network(f"{head}/{prefixlen}", strict=True)
            address = network.network_address
            if network.version == 6:
                address = ipaddress.IPv6Address(address.packed)
            return f"{address}/{network.prefixlen}"

        address = ipaddress.ip_address(head)
        if address.version == 6:
            address = ipaddress.IPv6Address(address.packed)
        return str(address)
    except ValueError:
        return None


def quote_shell_command(command: str, /, **values: t.Any) -> str:
    """Fill a trusted shell template and quote every resulting word.

    ``shlex.split`` honors quotes in the operator template, so
    ``vtysh -c "show bgp ... {target}"`` stays a single argument. Each word is
    formatted, then ``shlex.quote``d, which keeps the target one literal shell
    word when it contains spaces, quotes, ``$()``, or glob characters.

    Raises ``ValueError`` when the template's quotes do not parse.
    """
    words = [word.format(**values) for word in shlex.split(command)]
    return shlex.join(words)
