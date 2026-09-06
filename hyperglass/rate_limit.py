"""Atomic, shared admission control for device queries."""

# Standard Library
import math
import typing as t

# Third Party
from litestar.stores.redis import RedisStore
from litestar.datastructures import MutableScopeHeaders
from litestar.exceptions import TooManyRequestsException, ImproperlyConfiguredException
from litestar.middleware.rate_limit import DURATION_VALUES, RateLimitMiddleware

if t.TYPE_CHECKING:
    from litestar.connection import Request
    from litestar.types import Send, Scope, Message, Receive


# Check, increment, and set the first-request window's expiry in one operation.
# Rejected requests neither increment the counter nor extend the window.
ADMIT_SCRIPT = """
local count = tonumber(redis.call('GET', KEYS[1]) or '0')
local ttl = redis.call('PTTL', KEYS[1])
if ttl <= 0 then
    redis.call('SET', KEYS[1], 1, 'PX', ARGV[2])
    return {1, 1, tonumber(ARGV[2])}
end
if count >= tonumber(ARGV[1]) then
    return {0, count, ttl}
end
return {1, redis.call('INCR', KEYS[1]), ttl}
"""


class RateLimitStore(RedisStore):
    """Redis store with atomic admission across processes, not just shared data."""

    async def admit(self, key: str, limit: int, duration: int) -> t.Tuple[bool, int, int]:
        """Return admission, current usage, and milliseconds until reset."""
        allowed, count, ttl = await self._redis.eval(
            ADMIT_SCRIPT, 1, self._make_key(key), limit, duration * 1000
        )
        return bool(allowed), int(count), int(ttl)

    async def _shutdown(self) -> None:
        """Close the client using the API available in pinned redis-py 4.5."""
        if self.handle_client_shutdown:
            await self._redis.close()
            await self._redis.connection_pool.disconnect()


class QueryRateLimitMiddleware(RateLimitMiddleware):
    """Throttle by trusted ASGI client address with atomic Redis accounting."""

    def cache_key_from_request(self, request: "Request") -> str:
        """Use the server-resolved client, never untrusted forwarding headers."""
        host = request.client.host if request.client else "anonymous"
        # Separate schema from the old middleware's JSON histories on rollout.
        return f"query-rate-limit:v1:{self.unit}:{host}"

    async def __call__(self, scope: "Scope", receive: "Receive", send: "Send") -> None:
        """Admit a request only after the shared Redis budget has been consumed."""
        app = scope["app"]
        request = app.request_class(scope)
        if await self.should_check_request(request):
            store = self.config.get_store_from_app(app)
            if not isinstance(store, RateLimitStore):
                # A per-worker store or stock GET/SET implementation is not safe.
                raise ImproperlyConfiguredException("Query rate limiting requires RateLimitStore")
            allowed, count, ttl = await store.admit(
                self.cache_key_from_request(request), self.max_requests, DURATION_VALUES[self.unit]
            )
            policy = f"{self.max_requests}; w={DURATION_VALUES[self.unit]}"
            headers = {
                self.config.rate_limit_policy_header_key: policy,
                self.config.rate_limit_limit_header_key: str(self.max_requests),
                self.config.rate_limit_remaining_header_key: str(max(0, self.max_requests - count)),
                self.config.rate_limit_reset_header_key: str(max(0, math.ceil(ttl / 1000))),
            }
            if not allowed:
                raise TooManyRequestsException(
                    headers=headers if self.config.set_rate_limit_headers else None
                )
            if self.config.set_rate_limit_headers:
                original_send = send

                async def send_with_headers(message: "Message") -> None:
                    if message["type"] == "http.response.start":
                        response_headers = MutableScopeHeaders(message)
                        for key, value in headers.items():
                            response_headers.add(key, value)
                    await original_send(message)

                send = send_with_headers
        await self.app(scope, receive, send)
