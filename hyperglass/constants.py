"""Constant definitions used throughout the application."""

# Standard Library
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

# Characters that must never appear in a query target. Used at two points in
# the request pipeline (once at the type/validation boundary in
# `models.api.query`, again at the device-transport boundary in
# `execution.drivers._construct`) so a regression in either layer cannot let
# a CLI/shell metacharacter reach a device.
FORBIDDEN_TARGET_CHARS = frozenset(
    "\x00\x01\x02\x03\x04\x05\x06\x07\x08\t\n\x0b\x0c\r\x0e\x0f"
    "\x10\x11\x12\x13\x14\x15\x16\x17\x18\x19\x1a\x1b\x1c\x1d\x1e\x1f"
    "\x7f"  # DEL
    ";|&`<>\"\\"
)
