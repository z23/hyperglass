"""Query & parse data from bgp.tools.

- See https://bgp.tools/credits for acknowledgements and licensing.
- See https://bgp.tools/kb/api for query documentation.
"""

# Standard Library
import re
import typing as t
import asyncio
import hashlib
from ipaddress import IPv4Address, IPv6Address, ip_address

# Project
from hyperglass.log import log
from hyperglass.state import use_state

DEFAULT_KEYS = ("asn", "ip", "prefix", "country", "rir", "allocated", "org")

CACHE_KEY = "hyperglass.external.bgptools"

# How long a looked-up address is reused before bgp.tools is asked again.
CACHE_SECONDS = 24 * 60 * 60

# Upper bound for one whois exchange, connection included. The lookup runs in
# a background task after every query when webhooks are enabled, so an
# unresponsive server must not leave tasks and sockets open indefinitely.
WHOIS_TIMEOUT_SECONDS = 10


def _cache_key(target: str) -> str:
    """Build the cache key for one address.

    Each address has its own key so that it expires on its own. The address is
    hashed because the state store treats `.` in a key as a separator.
    """
    return f"{CACHE_KEY}.{hashlib.sha256(target.encode()).hexdigest()}"


TargetDetail = t.TypedDict(
    "TargetDetail",
    {"asn": str, "ip": str, "country": str, "rir": str, "allocated": str, "org": str},
)

TargetData = t.Dict[str, TargetDetail]


def default_ip_targets(*targets: str) -> t.Tuple[TargetData, t.Tuple[str, ...]]:
    """Construct a mapping of default data and other data that should be queried.

    Targets in the mapping don't need to be queried and already have default values. Targets in the
    query tuple should be queried.
    """
    default_data = {}
    query = ()
    for target in targets:
        detail: TargetDetail = dict.fromkeys(DEFAULT_KEYS, "None")
        try:
            valid: t.Union[IPv4Address, IPv6Address] = ip_address(target)

            checks = (
                (valid.version == 6 and valid.is_site_local, "Site Local Address"),
                (valid.is_loopback, "Loopback Address"),
                (valid.is_multicast, "Multicast Address"),
                (valid.is_link_local, "Link Local Address"),
                (valid.is_private, "Private Address"),
            )
            for exp, rir in checks:
                if exp is True:
                    detail["rir"] = rir
                    break

            should_query = any((valid.is_global, valid.is_unspecified, valid.is_reserved))

            if not should_query:
                detail["ip"] = str(target)
                default_data[str(target)] = detail
            elif should_query:
                query += (str(target),)

        except ValueError:
            pass

    return default_data, query


def parse_whois(output: str, targets: t.List[str]) -> TargetDetail:
    """Parse raw whois output from bgp.tools.

    Sample output:
    AS    | IP      | BGP Prefix | CC | Registry | Allocated  | AS Name
    13335 | 1.1.1.1 | 1.1.1.0/24 | US | ARIN     | 2010-07-14 | Cloudflare, Inc.
    """

    def lines(raw):
        """Generate clean string values for each column."""
        for r in (r for r in raw.split("\n") if r):
            fields = (re.sub(r"(\n|\r)", "", field).strip(" ") for field in r.split("|"))
            yield fields

    data = {}

    for line in lines(output):
        # Unpack each line's parsed values.
        asn, ip, prefix, country, rir, allocated, org = line

        # Match the line to the item in the list of resources to query.
        if ip in targets:
            i = targets.index(ip)
            data[targets[i]] = {
                "asn": asn,
                "ip": ip,
                "prefix": prefix,
                "country": country,
                "rir": rir,
                "allocated": allocated,
                "org": org,
            }
    log.bind(data=data).debug("Parsed bgp.tools data")
    return data


async def _whois_exchange(query: bytes) -> bytes:
    """Send a bulk whois query to bgp.tools and read the whole response."""
    reader, writer = await asyncio.open_connection("bgp.tools", port=43)
    try:
        writer.write(query)
        if writer.can_write_eof():
            writer.write_eof()
        await writer.drain()
        return await reader.read(-1)
    finally:
        log.debug("Closing connection to bgp.tools")
        writer.close()


async def run_whois(targets: t.List[str]) -> str:
    """Open raw socket to bgp.tools and execute query."""

    # Construct bulk query
    query = "\n".join(("begin", *targets, "end\n")).encode()

    log.debug("Opening connection to bgp.tools")
    response = await asyncio.wait_for(_whois_exchange(query), timeout=WHOIS_TIMEOUT_SECONDS)

    return response.decode()


async def network_info(*targets: str) -> TargetData:
    """Get ASN, Containing Prefix, and other info about an internet resource."""

    default_data, query_targets = default_ip_targets(*targets)

    cache = use_state("cache")

    # Set default data structure.
    query_data = {t: dict.fromkeys(DEFAULT_KEYS, "") for t in query_targets}

    # Try to use cached data for each of the items in the list of resources.
    uncached = []
    for target in query_targets:
        cached = cache.get(_cache_key(target))
        if cached is None:
            uncached.append(target)
            continue
        query_data[target] = cached
        log.bind(target=target).debug("Using cached network info")

    try:
        if uncached:
            whoisdata = await run_whois(uncached)

            if whoisdata:
                # If the response is not empty, parse it.
                query_data.update(parse_whois(whoisdata, uncached))

                # Cache the response
                for target in uncached:
                    key = _cache_key(target)
                    cache.set(key, query_data[target])
                    cache.expire(key, expire_in=CACHE_SECONDS)
                    log.bind(target=target).debug("Cached network info")

    except Exception as err:
        log.error(err)

    return {**default_data, **query_data}


def network_info_sync(*targets: str) -> TargetData:
    """Get ASN, Containing Prefix, and other info about an internet resource."""
    return asyncio.run(network_info(*targets))
