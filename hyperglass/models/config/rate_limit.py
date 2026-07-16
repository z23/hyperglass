"""Validation model for API rate-limit config."""

# Standard Library
import typing as t

# Third Party
from pydantic import Field

# Local
from ..main import HyperglassModel

if t.TYPE_CHECKING:
    # Third Party
    from litestar.stores.base import Store
    from litestar.middleware.rate_limit import RateLimitConfig

RateLimitPeriod = t.Literal["second", "minute", "hour", "day"]

# Rate limiting is scoped to the unauthenticated query endpoint. This pattern
# matches every path EXCEPT `/api/query`; Litestar excludes matching paths from
# rate limiting, so only `/api/query` is throttled (the UI, static assets, and
# read-only info endpoints are never limited).
RATE_LIMIT_EXCLUDE = [r"^(?!/api/query$).*"]

# Name under which the rate-limit store is registered on the Litestar app. The
# rate-limit middleware looks its store up from the app's store registry by this
# name; `hyperglass.api` registers a Redis-backed store here so the per-client
# counter is shared across worker processes (see `RateLimit.redis_store`).
RATE_LIMIT_STORE_NAME = "rate_limit"


class RateLimit(HyperglassModel):
    """Per-client rate limiting for the query API.

    The looking glass query endpoint is unauthenticated and each request opens a
    live connection to a network device, so it is rate limited by default to
    protect the backend and the devices from request floods.
    """

    enable: bool = Field(
        True,
        title="Enable Rate Limiting",
        description="Enable per-client rate limiting on the /api/query endpoint.",
    )
    period: RateLimitPeriod = Field(
        "minute",
        title="Rate Limit Period",
        description="Time window over which the request limit is applied.",
    )
    limit: int = Field(
        60,
        gt=0,
        title="Rate Limit",
        description="Maximum number of query requests allowed per client, per period.",
    )

    def to_litestar_config(self) -> t.Optional["RateLimitConfig"]:
        """Build a Litestar rate-limit config, or `None` when disabled.

        When disabled, no rate-limit middleware should be registered.
        """
        if not self.enable:
            return None

        # Third Party
        from litestar.middleware.rate_limit import RateLimitConfig

        return RateLimitConfig(
            rate_limit=(self.period, self.limit),
            exclude=RATE_LIMIT_EXCLUDE,
            store=RATE_LIMIT_STORE_NAME,
        )

    @staticmethod
    def redis_store(dsn: str) -> "Store":
        """Build a Redis-backed store for the rate-limit middleware.

        hyperglass runs multiple uvicorn workers in production (`cpu_count * 2`).
        Litestar's rate-limit middleware resolves its store from the app's store
        registry, which defaults to a per-process in-memory store; with that
        default each worker keeps its own counter and the effective limit
        becomes `workers * limit` (requests round-robin across workers, so the
        configured limit is never actually enforced). Backing the store with the
        Redis instance hyperglass already runs makes the counter shared, so the
        configured limit holds per client across every worker.
        """
        # Third Party
        from litestar.stores.redis import RedisStore

        return RedisStore.with_client(url=dsn)
