"""Validation model for API rate-limit config."""

# Standard Library
import typing as t

# Third Party
from pydantic import Field, AliasChoices
from pydantic_settings import BaseSettings, SettingsConfigDict

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


class RateLimit(BaseSettings):
    """Per-client rate limiting for the query API.

    The looking glass query endpoint is unauthenticated and each request opens a
    live connection to a network device, so it is rate limited by default to
    protect the backend and the devices from request floods.

    Values may be set in the config file (`rate_limit:` in `config.yaml`) or via
    environment variables (`HYPERGLASS_RATE_LIMIT`, `HYPERGLASS_RATE_LIMIT_PERIOD`,
    `HYPERGLASS_RATE_LIMIT_ENABLE`). The config file takes precedence per-field,
    then the environment variable, then the default.
    """

    model_config = SettingsConfigDict(
        env_prefix="hyperglass_rate_limit_",
        populate_by_name=True,
        extra="forbid",
    )

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
        10,
        gt=0,
        # Accept the concise `HYPERGLASS_RATE_LIMIT` env var (instead of the
        # prefixed `..._LIMIT`) and the `limit` key in the config file.
        validation_alias=AliasChoices("hyperglass_rate_limit", "limit"),
        title="Rate Limit",
        description="Maximum number of query requests allowed per client, per period.",
    )

    def __init__(self, **values: t.Any) -> None:
        # Normalize before BaseSettings merges sources, so the environment alias
        # cannot shadow the config-file key or leave it as a forbidden extra.
        if "limit" in values and "hyperglass_rate_limit" not in values:
            values["hyperglass_rate_limit"] = values.pop("limit")
        super().__init__(**values)

    def to_litestar_config(self) -> t.Optional["RateLimitConfig"]:
        """Build a Litestar rate-limit config, or `None` when disabled.

        When disabled, no rate-limit middleware should be registered.
        """
        if not self.enable:
            return None

        # Third Party
        from litestar.middleware.rate_limit import RateLimitConfig

        # Project
        from hyperglass.rate_limit import QueryRateLimitMiddleware

        return RateLimitConfig(
            rate_limit=(self.period, self.limit),
            exclude=RATE_LIMIT_EXCLUDE,
            store=RATE_LIMIT_STORE_NAME,
            middleware_class=QueryRateLimitMiddleware,
        )

    @staticmethod
    def redis_store(dsn: str) -> "Store":
        """Build a Redis-backed store for the rate-limit middleware.

        hyperglass runs multiple uvicorn workers in production (`cpu_count * 2`).
        Litestar's rate-limit middleware resolves its store from the app's store
        registry. Admission must also be atomic: sharing GET/SET histories alone
        allows simultaneous requests to consume the same remaining allowance.
        RateLimitStore performs the check, increment, and expiry in one Redis
        script, so the configured limit holds across worker processes.
        """
        # Third Party
        from redis.asyncio import Redis

        # Project
        from hyperglass.rate_limit import RateLimitStore

        return RateLimitStore(redis=Redis.from_url(dsn), handle_client_shutdown=True)
