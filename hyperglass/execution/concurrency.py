"""Per-device cap on in-flight queries, shared across worker processes."""

# Standard Library
import time
import typing as t
import secrets

# Project
from hyperglass.log import log

if t.TYPE_CHECKING:
    # Third Party
    from redis import Redis

    # Project
    from hyperglass.state import HyperglassState

# Each in-flight query is a member of a sorted set keyed by device, scored with
# its start time in milliseconds. Entries older than the TTL are pruned on every
# acquire, so a worker that dies mid-query cannot leak a slot forever. Check,
# prune and add happen in one script so concurrent workers cannot both take the
# last slot.
ACQUIRE_SCRIPT = """
redis.call('ZREMRANGEBYSCORE', KEYS[1], '-inf', tonumber(ARGV[1]) - tonumber(ARGV[3]))
local count = redis.call('ZCARD', KEYS[1])
if count >= tonumber(ARGV[4]) then
    return {0, count}
end
redis.call('ZADD', KEYS[1], ARGV[1], ARGV[2])
redis.call('PEXPIRE', KEYS[1], ARGV[3])
return {1, count + 1}
"""

KEY_PREFIX = "device.inflight"


class DeviceConcurrencyLimiter:
    """Atomic per-device admission for device queries."""

    def __init__(self, redis: "Redis", *, key: t.Callable[[str], str], ttl_seconds: int) -> None:
        """Initialize with a sync redis client, a key namespacer, and the slot TTL."""
        self._redis = redis
        self._key = key
        self._ttl_ms = max(1, int(ttl_seconds)) * 1000

    @classmethod
    def from_state(cls, state: "HyperglassState") -> "DeviceConcurrencyLimiter":
        """Build from hyperglass global state (shared Redis, request timeout)."""
        # A slot that is never released (worker crash) self-expires after twice
        # the request budget, which is longer than any legitimate query.
        ttl = max(5, int(state.params.request_timeout) * 2)
        return cls(state.redis.instance, key=state.redis.key, ttl_seconds=ttl)

    def _device_key(self, device_id: str) -> str:
        return self._key(f"{KEY_PREFIX}.{device_id}")

    def acquire(self, device_id: str, limit: int) -> t.Optional[str]:
        """Take a slot for `device_id`. Returns a release token, or None if full."""
        token = secrets.token_hex(8)
        now_ms = int(time.time() * 1000)
        allowed, count = self._redis.eval(
            ACQUIRE_SCRIPT, 1, self._device_key(device_id), now_ms, token, self._ttl_ms, int(limit)
        )
        _log = log.bind(device=device_id, in_flight=int(count), limit=int(limit))
        if not int(allowed):
            _log.warning("Device concurrency limit reached")
            return None
        _log.debug("Acquired device slot")
        return token

    def release(self, device_id: str, token: str) -> None:
        """Give a slot back. Safe to call more than once."""
        try:
            self._redis.zrem(self._device_key(device_id), token)
        except Exception as err:  # noqa: BLE001
            # The slot self-expires; never let release failure mask the query result.
            log.bind(device=device_id, error=str(err)).warning("Failed to release device slot")
