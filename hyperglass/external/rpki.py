"""Validate RPKI state via Cloudflare GraphQL API."""

# Standard Library
import typing as t
import hashlib

# Project
from hyperglass.log import log
from hyperglass.state import use_state
from hyperglass.external._base import BaseExternal

if t.TYPE_CHECKING:
    # Standard Library
    from ipaddress import IPv4Address, IPv6Address

RPKI_STATE_MAP = {"Invalid": 0, "Valid": 1, "NotFound": 2, "DEFAULT": 3}
RPKI_NAME_MAP = {v: k for k, v in RPKI_STATE_MAP.items()}
CACHE_KEY = "hyperglass.external.rpki"

# How long a validation result is reused. ROAs change, so a result must not be
# kept for the life of the Redis database.
CACHE_SECONDS = 60 * 60


def _cache_key(ro: str) -> str:
    """Build the cache key for one prefix and origin.

    Each result has its own key so that it expires on its own. The value is
    hashed because the state store treats `.` in a key as a separator.
    """
    return f"{CACHE_KEY}.{hashlib.sha256(ro.encode()).hexdigest()}"


def rpki_state(prefix: t.Union["IPv4Address", "IPv6Address", str], asn: t.Union[int, str]) -> int:
    """Get RPKI state and map to expected integer."""
    _log = log.bind(prefix=prefix, asn=asn)
    _log.debug("Validating RPKI State")

    cache = use_state("cache")

    state = 3
    ro = f"{prefix!s}@{asn!s}"

    key = _cache_key(ro)
    cached = cache.get(key)

    if cached is not None:
        state = cached
    else:
        ql = 'query GetValidation {{ validation(prefix: "{}", asn: {}) {{ state }} }}'
        query = ql.format(prefix, asn)
        _log.bind(query=query).debug("Cloudflare RPKI GraphQL Query")
        try:
            with BaseExternal(base_url="https://rpki.cloudflare.com") as client:
                response = client._post("/api/graphql", data={"query": query})
            try:
                validation_state = response["data"]["validation"]["state"]
            except KeyError as missing:
                _log.error("Response from Cloudflare missing key '{}': {!r}", missing, response)
                validation_state = 3

            state = RPKI_STATE_MAP[validation_state]
            cache.set(key, state)
            cache.expire(key, expire_in=CACHE_SECONDS)
        except Exception as err:
            log.error(err)
            # Don't cache the state when an error produced it.
            state = 3

    msg = "RPKI Validation State for {} via AS{} is {}".format(prefix, asn, RPKI_NAME_MAP[state])
    if cached is not None:
        msg += " [CACHED]"

    log.debug(msg)
    return state
